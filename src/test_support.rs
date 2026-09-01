//! Shared fixtures for unit tests across modules. Test-only (`cfg(test)`).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::{
    ClientInfo,
    config::ClientHost,
    deb_mirror::{Mirror, MirrorKind},
};

/// A structured mirror on the default port.
pub(crate) fn structured_mirror(host: &str, path: &str) -> Mirror {
    Mirror::new(
        ClientHost::new(host.to_owned()).expect("valid host"),
        None,
        path.to_owned(),
        MirrorKind::Structured,
    )
}

/// A loopback client, for code paths that only log or classify it.
pub(crate) fn local_client() -> ClientInfo {
    ClientInfo::new(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
}
