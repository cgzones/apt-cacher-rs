//! Per-host collision blocklist for the flat-repository layout.
//!
//! Every flat-repo file lives under `<cache>/<host>/flat/<mirror_path>/`,
//! the directory a structured mirror registered with `mirror_path = "flat"`
//! (or `"flat/<anything>"`) would write to.  When such a mirror exists,
//! **structured wins**: flat requests for that `(host, port)` are passed
//! through uncached.
//!
//! Dispatch relays a structured request under `flat` uncached
//! (`PassthroughReason::FlatAnchoredMirror`) and mints no origin, so no new
//! colliding mirror comes into being; the blocklist stays for rows recorded
//! before that rule.

use std::num::NonZero;
use std::sync::OnceLock;

use hashbrown::HashSet;
use parking_lot::RwLock;
use tracing::warn;

use crate::{
    cache_paths::{SUBDIR_FLAT, SUBDIR_FLAT_PREFIX},
    config::CacheHost,
    database::Database,
};

type Port = NonZero<u16>;

/// The host is the alias-resolved cache identity, so sibling aliases of the
/// same configured `main` share a single entry.
///
/// The set holds only rows recorded before dispatch stopped minting colliding
/// mirrors (empty on almost every install), so [`is_blocked`] scans it.
#[derive(Debug, Eq, Hash, PartialEq)]
struct BlocklistKey {
    host: CacheHost,
    port: Option<Port>,
}

static BLOCKLIST: OnceLock<RwLock<HashSet<BlocklistKey>>> = OnceLock::new();

/// Whether a mirror path collides with the host-anchored flat layout.  The
/// same predicate as the SQL in `database.rs` that hydrates the blocklist;
/// keep the two in sync.
#[must_use]
pub(crate) fn path_collides_with_flat_layout(path: &str) -> bool {
    path == SUBDIR_FLAT || path.starts_with(SUBDIR_FLAT_PREFIX)
}

/// Install the blocklist, seeded with the colliding mirror rows of the
/// database.
pub(crate) async fn init(database: &Database) -> Result<(), sqlx::Error> {
    let collision_rows = database.load_flat_collision_mirrors().await?;

    let mut set = HashSet::with_capacity(collision_rows.len());
    for entry in collision_rows {
        let port = entry.port();
        let path = entry.path.as_str();
        // Rows are canonical (alias-resolved at dispatch; legacy rows folded
        // by `merge_alias_rows` before this runs), so the row host *is* the
        // on-disk host directory the blocklist keys on.
        let resolved = entry.host.into_cache_host();

        warn!(
            "Structured mirror at {ha}/{path} collides with the host-level flat layout (found at startup); flat caching disabled for host {ha} (structured wins)",
            ha = resolved.format_authority(port)
        );
        set.insert(BlocklistKey {
            host: resolved,
            port,
        });
    }
    BLOCKLIST
        .set(RwLock::new(set))
        .expect("Initial set from main() should succeed");

    Ok(())
}

/// Block flat caching for `(host, port)` if `mirror_path` collides.  The DB
/// upsert calls this whenever the resulting row's `kind` is `Structured`:
/// on a fresh insert and on a previously-`Flat` row latching to
/// `Structured`, so a collision surfacing after a flat row existed is still
/// recorded.
pub(crate) fn record_mirror(host: &CacheHost, port: Option<Port>, mirror_path: &str) {
    if !path_collides_with_flat_layout(mirror_path) {
        return;
    }

    let was_new = BLOCKLIST
        .get()
        .expect("initialized in main()")
        .write()
        .insert(BlocklistKey {
            host: host.clone(),
            port,
        });
    if was_new {
        warn!(
            "Newly registered structured mirror at {ha}/{mirror_path} collides with the host-level flat layout; flat caching disabled for host {ha} (structured wins)",
            ha = host.format_authority(port)
        );
    }
}

#[must_use]
pub(crate) fn is_blocked(host: &CacheHost, port: Option<Port>) -> bool {
    BLOCKLIST
        .get()
        .expect("initialized in main()")
        .read()
        .iter()
        .any(|key| {
            let BlocklistKey {
                host: khost,
                port: kport,
            } = key;
            khost == host && *kport == port
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn path_collision_predicate() {
        assert!(path_collides_with_flat_layout("flat"));
        assert!(path_collides_with_flat_layout("flat/sub"));
        assert!(path_collides_with_flat_layout("flat/sub/deeper"));
        assert!(!path_collides_with_flat_layout(""));
        assert!(!path_collides_with_flat_layout("flatfoo"));
        assert!(!path_collides_with_flat_layout("foo/flat"));
        assert!(!path_collides_with_flat_layout("debian"));
    }
}
