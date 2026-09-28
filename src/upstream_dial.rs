//! Dialling an upstream host. Every TCP connection the proxy opens to a mirror
//! or a CONNECT target outside hyper's own connector goes through [`connect`]:
//! the splice backend's `tcp_connect` and both CONNECT relays.
//!
//! A name resolving to both address families is raced the way RFC 8305
//! ("Happy Eyeballs") describes, in the simplified form hyper-util's
//! `HttpConnector` implements, so every backend reaches a dual-stack mirror
//! alike (`main.rs` hands hyper's connector the same [`FALLBACK_DELAY`]). The
//! addresses of the resolver's first family (RFC 6724 puts IPv6 first where
//! the host has an IPv6 route) are tried in order; the other family's start
//! [`FALLBACK_DELAY`] later, or at once when the first family has failed. The
//! first connection wins and dropping the losers closes their sockets. Tried
//! one after another instead, a host whose IPv6 path silently drops packets
//! waits out the whole connect timeout on its AAAA record and never reaches
//! the A record.
//!
//! Each family spreads what is left of the timeout over the addresses it has
//! still to try, so a dead first address cannot starve the rest of its family.
//! A failed dial reports every address it tried, not only the last one.

use std::{
    fmt,
    future::Future,
    io::{self, ErrorKind},
    net::SocketAddr,
    time::Duration,
};

use tokio::{
    net::{TcpStream, lookup_host},
    time::{Instant, error::Elapsed},
};

use crate::{error::ErrorReport, humanfmt::HumanFmt, metrics};

/// How long the resolver's first address family runs alone before the other
/// family joins the race: hyper-util's default, which `main.rs` pins on
/// hyper's connector so the backends agree.
pub(crate) const FALLBACK_DELAY: Duration = Duration::from_millis(300);

/// Resolve `host` and connect to `host:port` within `timeout`, racing the two
/// address families (see the module doc).
///
/// `host` is the bare host text (`DomainName::as_str()`): an IPv6 address
/// without brackets, which the resolver takes as a literal.
///
/// A dial that gives up because every attempt ran out of time fails with
/// [`ErrorKind::TimedOut`] and counts once in
/// `metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT`; any other failure carries the
/// kind of the last attempt that did not time out.
pub(crate) async fn connect(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    let addrs: Vec<SocketAddr> =
        match tokio::time::timeout_at(deadline, lookup_host((host, port))).await {
            Ok(addrs) => addrs?.collect(),
            Err(_elapsed @ Elapsed { .. }) => {
                metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT.increment();
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    format!(
                        "name resolution timed out after {}",
                        HumanFmt::Time(timeout)
                    ),
                ));
            }
        };

    race(
        &addrs,
        deadline,
        FALLBACK_DELAY,
        TcpStream::connect::<SocketAddr>,
    )
    .await
    .inspect_err(|err| {
        if err.kind() == ErrorKind::TimedOut {
            metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT.increment();
        }
    })
}

/// Race the resolved `addrs` by family (the module doc), each attempt through
/// `connect`, until one succeeds or all have failed by `deadline`.
///
/// Generic over the connection so the race is testable without a network.
async fn race<S, F, Fut>(
    addrs: &[SocketAddr],
    deadline: Instant,
    fallback_delay: Duration,
    connect: F,
) -> io::Result<S>
where
    S: Send,
    F: Fn(SocketAddr) -> Fut + Sync,
    Fut: Future<Output = io::Result<S>> + Send,
{
    let Some(first) = addrs.first() else {
        return Err(io::Error::new(
            ErrorKind::NotFound,
            "the host name resolved to no address",
        ));
    };
    let (preferred, fallback): (Vec<SocketAddr>, Vec<SocketAddr>) = addrs
        .iter()
        .partition(|addr| addr.is_ipv6() == first.is_ipv6());

    let preferred_attempts = sequence(&preferred, deadline, &connect);
    if fallback.is_empty() {
        return preferred_attempts.await.map_err(DialFailure::into_error);
    }
    tokio::pin!(preferred_attempts);

    // The preferred family's head start; its failure ends it early.
    tokio::select! {
        result = &mut preferred_attempts => {
            return match result {
                Ok(stream) => Ok(stream),
                Err(preferred_failed) => sequence(&fallback, deadline, &connect)
                    .await
                    .map_err(|fallback_failed| preferred_failed.merge(fallback_failed).into_error()),
            };
        }
        () = tokio::time::sleep(fallback_delay) => {}
    }

    let fallback_attempts = sequence(&fallback, deadline, &connect);
    tokio::pin!(fallback_attempts);
    tokio::select! {
        result = &mut preferred_attempts => match result {
            Ok(stream) => Ok(stream),
            Err(preferred_failed) => fallback_attempts
                .await
                .map_err(|fallback_failed| preferred_failed.merge(fallback_failed).into_error()),
        },
        result = &mut fallback_attempts => match result {
            Ok(stream) => Ok(stream),
            Err(fallback_failed) => preferred_attempts
                .await
                .map_err(|preferred_failed| preferred_failed.merge(fallback_failed).into_error()),
        },
    }
}

/// Try `addrs` one after another, each within an equal share of the time left
/// until `deadline` among the addresses still untried.
async fn sequence<S, F, Fut>(
    addrs: &[SocketAddr],
    deadline: Instant,
    connect: &F,
) -> Result<S, DialFailure>
where
    S: Send,
    F: Fn(SocketAddr) -> Fut + Sync,
    Fut: Future<Output = io::Result<S>> + Send,
{
    let mut failure = DialFailure {
        attempts: Vec::with_capacity(addrs.len()),
    };
    for (index, &addr) in addrs.iter().enumerate() {
        let untried = u32::try_from(addrs.len() - index).unwrap_or(u32::MAX);
        let share = deadline.saturating_duration_since(Instant::now()) / untried;
        let outcome = match tokio::time::timeout(share, connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => AttemptError::Failed(err),
            Err(_elapsed @ Elapsed { .. }) => AttemptError::TimedOut(share),
        };
        failure.attempts.push((addr, outcome));
    }
    Err(failure)
}

/// Why one address was given up on.
#[derive(Debug)]
enum AttemptError {
    Failed(io::Error),
    TimedOut(Duration),
}

/// Every address a failed dial tried, in the order the two families started.
#[derive(Debug)]
struct DialFailure {
    attempts: Vec<(SocketAddr, AttemptError)>,
}

impl DialFailure {
    fn merge(mut self, other: Self) -> Self {
        let Self { attempts } = other;
        self.attempts.extend(attempts);
        self
    }

    /// `TimedOut` only when every attempt ran out of time: a refusal or an
    /// unreachable network says more about why the host cannot be reached.
    fn kind(&self) -> ErrorKind {
        self.attempts
            .iter()
            .rev()
            .find_map(|(_, outcome)| match outcome {
                AttemptError::Failed(err) => Some(err.kind()),
                AttemptError::TimedOut(_) => None,
            })
            .unwrap_or(ErrorKind::TimedOut)
    }

    fn into_error(self) -> io::Error {
        io::Error::new(self.kind(), self)
    }
}

impl fmt::Display for DialFailure {
    /// `addr:  cause` per attempt, comma-separated; an IPv6 address renders
    /// bracketed (`[2001:db8::1]:80`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { attempts } = self;
        for (index, (addr, outcome)) in attempts.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            match outcome {
                AttemptError::Failed(err) => write!(f, "{addr}:  {}", ErrorReport(err))?,
                AttemptError::TimedOut(after) => {
                    write!(f, "{addr}:  timed out after {}", HumanFmt::Time(*after))?;
                }
            }
        }
        Ok(())
    }
}

impl std::error::Error for DialFailure {}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use parking_lot::Mutex;

    use super::*;

    const V6_A: SocketAddr = SocketAddr::new(std::net::IpAddr::V6(Ipv6Addr::LOCALHOST), 80);
    const V6_B: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        80,
    );
    const V4_A: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 80);
    const V4_B: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 80);

    /// How a fake connect answers one address.
    #[derive(Clone, Copy)]
    enum Behaviour {
        Connects,
        Refuses,
        Hangs,
    }

    /// A fake dial: each address behaves as listed, and the order in which
    /// attempts started is recorded.
    struct Fake {
        behaviour: Vec<(SocketAddr, Behaviour)>,
        started: Mutex<Vec<(SocketAddr, Instant)>>,
    }

    impl Fake {
        fn new(behaviour: &[(SocketAddr, Behaviour)]) -> Self {
            Self {
                behaviour: behaviour.to_vec(),
                started: Mutex::new(Vec::new()),
            }
        }

        async fn connect(&self, addr: SocketAddr) -> io::Result<SocketAddr> {
            self.started.lock().push((addr, Instant::now()));
            let behaviour = self
                .behaviour
                .iter()
                .find_map(|&(candidate, behaviour)| (candidate == addr).then_some(behaviour))
                .expect("address listed");
            match behaviour {
                Behaviour::Connects => Ok(addr),
                Behaviour::Refuses => Err(io::Error::from(ErrorKind::ConnectionRefused)),
                Behaviour::Hangs => std::future::pending().await,
            }
        }

        fn started(&self) -> Vec<SocketAddr> {
            self.started.lock().iter().map(|&(addr, _)| addr).collect()
        }
    }

    async fn run(
        fake: &Fake,
        addrs: &[SocketAddr],
        timeout: Duration,
        fallback_delay: Duration,
    ) -> io::Result<SocketAddr> {
        race(addrs, Instant::now() + timeout, fallback_delay, |addr| {
            fake.connect(addr)
        })
        .await
    }

    /// The motivating case: a blackholed IPv6 address does not hold up the
    /// IPv4 one past the fallback delay.
    #[tokio::test]
    async fn a_hanging_preferred_family_falls_back_after_the_delay() {
        let fake = Fake::new(&[(V6_A, Behaviour::Hangs), (V4_A, Behaviour::Connects)]);
        let start = Instant::now();
        let delay = Duration::from_millis(50);
        let winner = run(&fake, &[V6_A, V4_A], Duration::from_secs(30), delay)
            .await
            .unwrap();
        assert_eq!(winner, V4_A);
        assert_eq!(fake.started(), [V6_A, V4_A]);
        let fallback_start = fake.started.lock()[1].1;
        assert!(fallback_start - start >= delay, "fallback started early");
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "waited for the timeout"
        );
    }

    /// A refused preferred family hands over at once instead of waiting out
    /// the delay.
    #[tokio::test]
    async fn a_failed_preferred_family_falls_back_immediately() {
        let fake = Fake::new(&[(V6_A, Behaviour::Refuses), (V4_A, Behaviour::Connects)]);
        let start = Instant::now();
        let winner = run(
            &fake,
            &[V6_A, V4_A],
            Duration::from_secs(30),
            Duration::from_secs(20),
        )
        .await
        .unwrap();
        assert_eq!(winner, V4_A);
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "waited out the delay"
        );
    }

    /// The preferred family is the resolver's first one, IPv4 included.
    #[tokio::test]
    async fn the_first_resolved_family_goes_first() {
        let fake = Fake::new(&[(V4_A, Behaviour::Connects), (V6_A, Behaviour::Connects)]);
        let winner = run(
            &fake,
            &[V4_A, V6_A],
            Duration::from_secs(30),
            Duration::from_secs(20),
        )
        .await
        .unwrap();
        assert_eq!(winner, V4_A);
        assert_eq!(fake.started(), [V4_A]);
    }

    /// Within one family a hanging address gets only its share of the
    /// timeout, so the next one is still tried.
    #[tokio::test]
    async fn a_hanging_address_leaves_time_for_the_rest_of_its_family() {
        let fake = Fake::new(&[(V6_A, Behaviour::Hangs), (V6_B, Behaviour::Connects)]);
        let winner = run(
            &fake,
            &[V6_A, V6_B],
            Duration::from_millis(400),
            FALLBACK_DELAY,
        )
        .await
        .unwrap();
        assert_eq!(winner, V6_B);
    }

    /// A failed dial names every address it tried, and takes its kind from a
    /// real failure over a timeout.
    #[tokio::test]
    async fn a_failed_dial_reports_every_attempt() {
        let fake = Fake::new(&[
            (V6_A, Behaviour::Hangs),
            (V4_A, Behaviour::Refuses),
            (V4_B, Behaviour::Refuses),
        ]);
        let err = run(
            &fake,
            &[V6_A, V4_A, V4_B],
            Duration::from_millis(200),
            Duration::from_millis(20),
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
        let report = ErrorReport(&err).to_string();
        assert!(
            report.starts_with("[::1]:80:  timed out after "),
            "{report}"
        );
        assert!(
            report.contains(", 127.0.0.1:80:  connection refused"),
            "{report}"
        );
        assert!(
            report.ends_with(", 192.0.2.2:80:  connection refused"),
            "{report}"
        );
    }

    /// Only a dial on which every attempt ran out of time is a timeout.
    #[tokio::test]
    async fn a_dial_of_only_timeouts_is_a_timeout() {
        let fake = Fake::new(&[(V6_A, Behaviour::Hangs), (V4_A, Behaviour::Hangs)]);
        let err = run(
            &fake,
            &[V6_A, V4_A],
            Duration::from_millis(100),
            Duration::from_millis(20),
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn no_address_is_an_error() {
        let fake = Fake::new(&[]);
        let err = run(&fake, &[], Duration::from_secs(1), FALLBACK_DELAY)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }

    /// End to end over real sockets: a refused IPv6 loopback port falls
    /// through to a listening IPv4 one resolved for the same "name".
    #[tokio::test]
    async fn a_refused_ipv6_address_falls_through_to_ipv4() {
        let Ok(v6) = std::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) else {
            return; // no IPv6 loopback on this host
        };
        let v6_addr = v6.local_addr().unwrap();
        drop(v6); // nothing listens there any more: a connect is refused
        let v4 = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let v4_addr = v4.local_addr().unwrap();

        let stream = race(
            &[v6_addr, v4_addr],
            Instant::now() + Duration::from_secs(10),
            FALLBACK_DELAY,
            TcpStream::connect::<SocketAddr>,
        )
        .await
        .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), v4_addr);
    }

    /// A bracket-less IPv6 literal is dialled as an address, without a
    /// resolver.
    #[tokio::test]
    async fn connect_dials_a_bare_ipv6_literal() {
        let Ok(listener) = tokio::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await else {
            return; // no IPv6 loopback on this host
        };
        let port = listener.local_addr().unwrap().port();
        let stream = connect("::1", port, Duration::from_secs(10)).await.unwrap();
        assert_eq!(
            stream.peer_addr().unwrap(),
            SocketAddr::from((Ipv6Addr::LOCALHOST, port))
        );
    }
}
