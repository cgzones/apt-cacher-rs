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
        path.to_owned(),
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
