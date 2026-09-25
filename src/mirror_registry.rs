//! A bounded in-memory map of per-mirror state since process start, the
//! storage behind the dashboard's per-mirror columns (`mirror_health`, and
//! every other since-start figure the Mirrors table joins in).
//!
//! Keyed by the canonical [`Mirror`] itself: a recording site hands in the
//! `&Mirror` it already holds, the lookup hashes it in place, and only the
//! first sighting of a mirror clones it into the map. One short uncontended
//! lock per record, never held across an `.await`.
//!
//! A snapshot renders each key as `host[:port]/path` -- the Mirrors table's
//! `MirrorUri`, so rows join by string -- and folds the entries that render
//! alike into one ([`Twin::merge`]): a mirror's flat and structured
//! requests are two `Mirror`s (the kind is part of its identity) but one
//! table row.
//!
//! In memory only: a restart forgets everything, like every other
//! process-lifetime metric. The map is capped at a number of distinct
//! mirrors; a mirror first seen past the cap is not tracked.

use std::sync::LazyLock;

use hashbrown::HashMap;

use crate::deb_mirror::Mirror;

/// Per-mirror state two twins (the same `host[:port]/path`, different
/// kinds) fold into one snapshot entry through.
pub(crate) trait Twin {
    /// Fold `other`, a twin's state, into `self`.
    fn merge(&mut self, other: &Self);
}

/// Distinct mirrors a registry tracks by default. Mirrors are bounded by
/// `allowed_mirrors` and the paths clients use on them, far below this; the
/// cap only keeps a wildcard allowlist from turning traffic into unbounded
/// memory.
pub(crate) const MAX_MIRRORS: usize = 1024;

/// See the module doc.
pub(crate) struct MirrorRegistry<T> {
    map: LazyLock<parking_lot::Mutex<HashMap<Mirror, T>>>,
    cap: usize,
}

impl<T: Default + Clone + Twin> MirrorRegistry<T> {
    #[must_use]
    pub(crate) const fn new(cap: usize) -> Self {
        Self {
            map: LazyLock::new(|| parking_lot::Mutex::new(HashMap::new())),
            cap,
        }
    }

    /// Apply `update` to `mirror`'s state, creating it (at its default) on
    /// the first sighting unless the registry is full.
    pub(crate) fn update(&self, mirror: &Mirror, update: impl FnOnce(&mut T)) {
        let mut map = self.map.lock();
        if let Some(state) = map.get_mut(mirror) {
            update(state);
        } else if map.len() < self.cap {
            update(map.entry(mirror.clone()).or_default());
        }
    }

    /// Every tracked mirror's state keyed by its `host[:port]/path`
    /// rendering, twins merged, for one dashboard render.
    #[must_use]
    pub(crate) fn snapshot(&self) -> HashMap<Box<str>, T> {
        // Cloned under the lock, rendered outside it.
        let entries: Vec<(Mirror, T)> = self
            .map
            .lock()
            .iter()
            .map(|(mirror, state)| (mirror.clone(), state.clone()))
            .collect();
        let mut snapshot: HashMap<Box<str>, T> = HashMap::with_capacity(entries.len());
        for (mirror, state) in entries {
            match snapshot.entry(mirror.to_string().into_boxed_str()) {
                hashbrown::hash_map::Entry::Occupied(mut twin) => twin.get_mut().merge(&state),
                hashbrown::hash_map::Entry::Vacant(slot) => {
                    slot.insert(state);
                }
            }
        }
        snapshot
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::ClientHost, deb_mirror::MirrorKind};

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    struct Tally(u64);
    impl Twin for Tally {
        fn merge(&mut self, other: &Self) {
            self.0 += other.0;
        }
    }

    fn mirror(host: &str, path: &str, kind: MirrorKind) -> Mirror {
        Mirror::new(
            ClientHost::new(host.to_owned()).expect("valid host"),
            None,
            path.to_owned(),
            kind,
        )
    }

    #[test]
    fn a_mirror_is_tracked_per_identity_and_rendered_by_uri() {
        let registry = MirrorRegistry::<Tally>::new(8);
        let a = mirror("a.example", "debian", MirrorKind::Structured);
        registry.update(&a, |t| t.0 += 1);
        registry.update(&a, |t| t.0 += 1);
        registry.update(
            &mirror("b.example", "ubuntu", MirrorKind::Structured),
            |t| {
                t.0 += 5;
            },
        );
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.get("a.example/debian"), Some(&Tally(2)));
        assert_eq!(snapshot.get("b.example/ubuntu"), Some(&Tally(5)));
    }

    /// A mirror's flat and structured requests are two keys but one row.
    #[test]
    fn twins_that_render_alike_merge_in_the_snapshot() {
        let registry = MirrorRegistry::<Tally>::new(8);
        registry.update(&mirror("a.example", "repo", MirrorKind::Structured), |t| {
            t.0 += 1;
        });
        registry.update(&mirror("a.example", "repo", MirrorKind::Flat), |t| t.0 += 2);
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot.get("a.example/repo"), Some(&Tally(3)));
    }

    #[test]
    fn a_mirror_past_the_cap_is_not_tracked_but_known_ones_still_count() {
        let registry = MirrorRegistry::<Tally>::new(1);
        let a = mirror("a.example", "", MirrorKind::Structured);
        let b = mirror("b.example", "", MirrorKind::Structured);
        registry.update(&a, |t| t.0 += 1);
        registry.update(&b, |t| t.0 += 1);
        registry.update(&a, |t| t.0 += 1);
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot.get("a.example/"), Some(&Tally(2)));
    }
}
