//! Per-host collision blocklist for the flat-repository layout.
//!
//! The host-anchored flat layout places every flat-repo file under
//! `<cache>/<host>/flat/<mirror_path>/`.  That `<host>/flat/` directory is
//! the same one a structured mirror registered with `mirror_path = "flat"`
//! (or `"flat/<anything>"`) would write to — `<cache>/<host>/flat/dists/…`,
//! `<cache>/<host>/flat/pool/…`, etc.
//!
//! When such a collision exists, **structured wins**: flat requests for the
//! affected host are rejected and fall through to the simple-proxy
//! passthrough path.  This module owns the in-memory set of blocked
//! `(host, port)` pairs.
//!
//! The blocklist replaces the deleted `flat_registry`'s role in
//! disambiguating flat URLs, but is dramatically simpler: it's a flat set
//! that records "this host has a colliding structured mirror" rather than
//! a longest-prefix index that rewrites every flat-pool URL.
//!
//! # Lifecycle
//!
//! - **Init**: `main()` calls [`init`] once at startup with the seed set
//!   hydrated from a `SELECT … WHERE path = 'flat' OR path LIKE 'flat/%'`
//!   query.  Logs one `warn!` per colliding mirror so operators see the
//!   collision in the daemon's startup log.
//! - **Maintenance**: [`record_mirror`] is called from
//!   `upsert_mirror_get_id` whenever the post-upsert row's `kind`
//!   column is `Structured` (0).  That covers both fresh inserts and
//!   the ON-CONFLICT path that latches a previously-`Flat` row to
//!   `Structured`, so a collision that only surfaces after a flat
//!   row already existed is still recorded.  Inserts the host into
//!   the blocklist if the path matches the collision pattern.
//! - **Lookup**: [`is_blocked`] is called from request classifiers after
//!   a [`crate::cache_layout::CacheLayout::Flat`] / `FlatByHash` result
//!   is produced.  Returns `true` if the (host, port) is in the set,
//!   instructing the caller to pass through uncached.

use std::num::NonZero;
use std::sync::OnceLock;

use hashbrown::{Equivalent, HashSet};
use log::warn;
use parking_lot::RwLock;

use crate::{
    cache_layout::{SUBDIR_FLAT, SUBDIR_FLAT_PREFIX},
    config::{CacheHost, resolve_alias},
    database::Database,
    global_config,
};

type Port = NonZero<u16>;

/// (host, port) entry shape used as the blocklist key.  The host is the
/// alias-resolved cache identity, so sibling aliases of the same
/// configured `main` share a single entry.
#[derive(Debug, Eq, Hash, PartialEq)]
struct BlocklistKey {
    host: CacheHost,
    port: Option<Port>,
}

/// Borrowed counterpart to [`BlocklistKey`] used for read-side lookups via
/// `hashbrown::Equivalent`, so hot-path `is_blocked` callers do not need
/// to clone the `CacheHost` on every flat request.
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

/// Process-wide handle to the singleton blocklist.  Installed once by
/// [`init`]; subsequent callers borrow the inner `RwLock`.
static BLOCKLIST: OnceLock<RwLock<HashSet<BlocklistKey>>> = OnceLock::new();

/// Whether a mirror path collides with the host-anchored flat layout
/// (i.e. `path == "flat"` or `path` begins with `"flat/"`).  Pulled out
/// so both the DB hydration query and the in-process [`record_mirror`]
/// path apply the same predicate.
#[must_use]
pub(crate) fn path_collides_with_flat_layout(path: &str) -> bool {
    path == SUBDIR_FLAT || path.starts_with(SUBDIR_FLAT_PREFIX)
}

/// Install the blocklist singleton.
pub(crate) async fn init(database: &Database) -> Result<(), sqlx::Error> {
    let collision_rows = database.load_flat_collision_mirrors().await?;

    let aliases = global_config().aliases.as_slice();
    let mut set = HashSet::with_capacity(collision_rows.len());
    for entry in collision_rows {
        let port = entry.port();
        let path = entry.path.as_str();
        // Key the blocklist on the alias-resolved host (the same identity
        // `ConnectionDetails::cache_dir_path` uses for the on-disk host
        // directory), so a structured mirror registered via one alias also
        // blocks flat requests arriving via sibling aliases of the same
        // main host.
        let resolved: CacheHost = match resolve_alias(aliases, &entry.host) {
            Some(c) => c.clone(),
            None => entry.host.into_cache_host(),
        };

        warn!(
            "Structured mirror at `{ha}/{path}` collides with host-level flat layout - flat caching disabled for host `{ha}` (structured wins)",
            ha = resolved.format_cache_dir(port)
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

/// Append a (host, port) entry if `mirror_path` matches the collision
/// pattern.  Called from the DB upsert path whenever the post-upsert
/// row's `kind` column is `Structured` — that gate fires both on
/// fresh inserts and on an UPDATE that latches an existing row from
/// `Flat` back to `Structured`, so the blocklist sees the collision
/// even when it surfaced after a flat row already existed.  The
/// `HashSet::insert` is idempotent, so repeat calls cost only a write
/// lock + lookup.
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
            "Structured mirror at `{ha}/{mirror_path}` collides with host-level flat layout - flat caching disabled for host `{ha}` (structured wins)",
            ha = host.format_cache_dir(port)
        );
    }
}

/// Whether flat caching is blocked for the given `(host, port)` pair.
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
