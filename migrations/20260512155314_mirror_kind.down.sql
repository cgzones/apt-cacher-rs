-- SQLite gained ALTER TABLE DROP COLUMN in 3.35.0 (2021-03-12).  Any
-- `kind = 1` rows survive the drop, but the blocklist seed semantics on
-- the old schema were "anything at `path = 'flat[/%]'` is a collision"
-- — for any such rows that were *actually* flat mirrors, downgrading
-- reintroduces the original self-block false positive.
ALTER TABLE mirrors_v2 DROP COLUMN kind;
