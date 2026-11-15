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

use hashbrown::{Equivalent, HashSet};
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
#[derive(Debug, Eq, Hash, PartialEq)]
struct BlocklistKey {
    host: CacheHost,
    port: Option<Port>,
}

/// Borrowed lookup form of [`BlocklistKey`], so `is_blocked` clones no
/// `CacheHost` per flat request.
#[derive(Hash)]
struct BlocklistKeyRef<'a> {
    host: &'a CacheHost,
    port: Option<Port>,
}

impl Equivalent<BlocklistKey> for BlocklistKeyRef<'_> {
    fn equivalent(&self, key: &BlocklistKey) -> bool {
        let &Self { host, port } = self;
        let BlocklistKey {
            host: khost,
            port: kport,
        } = key;
        host == khost && port == *kport
    }
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
        .contains(&BlocklistKeyRef { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientHost;

    /// The borrowed lookup key must hash and compare exactly like the owned
    /// one it stands in for; a mismatch would make every `is_blocked` query
    /// miss silently instead of failing loudly.
    #[test]
    fn borrowed_key_matches_owned_entry() {
        let host = ClientHost::new("apt.example.org")
            .expect("valid host")
            .into_cache_host();
        let other = ClientHost::new("apt.example.net")
            .expect("valid host")
            .into_cache_host();
        let port = NonZero::new(8080);

        let mut set: HashSet<BlocklistKey> = HashSet::new();
        set.insert(BlocklistKey {
            host: host.clone(),
            port,
        });

        assert!(set.contains(&BlocklistKeyRef { host: &host, port }));
        // Both halves of the key take part in the match.
        assert!(!set.contains(&BlocklistKeyRef {
            host: &host,
            port: None
        }));
        assert!(!set.contains(&BlocklistKeyRef { host: &other, port }));
    }

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
