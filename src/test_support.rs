//! Shared fixtures for unit tests across modules. Test-only (`cfg(test)`).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::{
    cache_layout::{ConnectionDetails, ResourceKind},
    client_info::ClientInfo,
    config::ClientHost,
    deb_mirror::{Mirror, MirrorKind},
    precise_instant::PreciseInstant,
};

/// A structured mirror on the default port.
pub(crate) fn structured_mirror(host: &str, path: &str) -> Mirror {
    Mirror::new(
        ClientHost::new(host).expect("valid host"),
        None,
        path.into(),
        MirrorKind::Structured,
    )
}

/// A loopback client, for code paths that only log or classify it.
pub(crate) fn local_client() -> ClientInfo {
    ClientInfo::new(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
}

/// A minimal request context for the log/bookkeeping sites that only read
/// `debname`, `mirror` and `client` off it.
pub(crate) fn connection_details(debname: &str) -> ConnectionDetails {
    let mirror = structured_mirror("fixture.test", "/debian");
    ConnectionDetails {
        client: local_client(),
        request_received_at: PreciseInstant::now(),
        upstream_host: mirror.host().clone(),
        mirror,
        debname: debname.to_owned(),
        resource_kind: ResourceKind::Pool,
        origin_fields: None,
    }
}

/// Collect the levels of every event emitted while `f` runs. The delivery
/// sinks pick their level from `DeliveryFailure::severity`, so a test asserts
/// the policy by reading the levels back off the subscriber.
pub(crate) fn levels_during(f: impl FnOnce()) -> Vec<tracing::Level> {
    use std::sync::Arc;

    use parking_lot::Mutex;
    use tracing::{
        Event, Metadata, Subscriber,
        span::{Attributes, Id, Record},
    };

    struct Levels(Mutex<Vec<tracing::Level>>);
    impl Subscriber for Levels {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            self.0.lock().push(*event.metadata().level());
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    let levels = Arc::new(Levels(Mutex::new(Vec::new())));
    let guard = tracing::subscriber::set_default(Arc::clone(&levels));
    f();
    drop(guard);
    levels.0.lock().clone()
}

/// Occupy the sole blocking worker until the returned sender is sent or dropped.
/// Configure `max_blocking_threads(1)` and finish prerequisite blocking I/O
/// before calling; release the sender before tearing down the runtime.
#[cfg(feature = "splice")]
pub(crate) fn pause_blocking_pool(
    runtime: &tokio::runtime::Runtime,
) -> std::sync::mpsc::Sender<()> {
    let (resume, paused) = std::sync::mpsc::channel();
    let (started, ready) = std::sync::mpsc::channel();
    drop(runtime.spawn_blocking(move || {
        started.send(()).unwrap();
        let _released = paused.recv();
    }));
    ready.recv().unwrap();
    resume
}

/// Encode and finalize a gzip fixture using the default compression level.
pub(crate) async fn gzip(raw: &[u8]) -> Vec<u8> {
    use async_compression::tokio::write::GzipEncoder;
    use tokio::io::AsyncWriteExt as _;

    let mut encoder = GzipEncoder::new(Vec::new());
    encoder.write_all(raw).await.expect("gzip write");
    encoder.shutdown().await.expect("gzip finish");
    encoder.into_inner()
}

/// A connected loopback TCP pair, returned as (connecting socket, accepted socket).
#[cfg(feature = "splice")]
pub(crate) async fn connected_tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let connected =
        tokio::net::TcpStream::connect(listener.local_addr().expect("listener address"))
            .await
            .expect("loopback connection");
    let (accepted, _) = listener.accept().await.expect("accept loopback connection");
    (connected, accepted)
}

/// Run a FIFO read with no writer, failing without stranding a blocking open
/// during runtime shutdown. A regression to a blocking read can outlive the
/// timed-out future, including `Release`'s whole-read blocking job.
pub(crate) fn fifo_read_timeout<T>(path: &std::path::Path, read: impl Future<Output = T>) -> T {
    use std::time::Duration;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("FIFO test runtime");
    let result =
        runtime.block_on(async { tokio::time::timeout(Duration::from_secs(5), read).await });
    if result.is_err() {
        // O_RDWR|O_NONBLOCK needs no peer and releases an original
        // O_RDONLY open. Keep it alive while the blocking job resumes;
        // bound shutdown too if that older job then waits in a read.
        let peer = crate::fs_open::nofollow_nonblock_options()
            .read(true)
            .write(true)
            .open(path)
            .expect("open FIFO recovery peer");
        runtime.shutdown_timeout(Duration::from_secs(1));
        // An older whole-read job now sees EOF and can finish too.
        drop(peer);
    }
    result.expect("FIFO read waited for a writer")
}

/// Permit an IPv6 integration test to skip only when the host lacks IPv6
/// and this run has not required it (CI sets the environment flag).
pub(crate) fn assert_ipv6_unavailable(err: &std::io::Error) {
    assert!(
        crate::main_loop::is_missing_ipv6(err),
        "unexpected IPv6 bind failure: {err}"
    );
    assert_ne!(
        std::env::var_os("APT_CACHER_RS_REQUIRE_IPV6").as_deref(),
        Some(std::ffi::OsStr::new("1")),
        "IPv6 is required for this test run: {err}"
    );
}
