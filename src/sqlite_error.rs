//! Names for SQLite result codes and a log renderer for `sqlx::Error`.
//!
//! SQLite has no API that turns a result code back into its symbolic name:
//! `sqlite3_errstr()` is indexed by the primary code (`code & 0xff`), so for
//! an extended code it returns the same generic text the error already
//! carries (`disk I/O error` for `SQLITE_IOERR_GETTEMPPATH`). The name is
//! what an operator needs, so [`CODE_NAMES`] mirrors the `#define`s of the
//! bundled `sqlite3.h`. The numeric values are public ABI and never
//! renumbered; a bump of the bundled SQLite can only append entries.
//!
//! [`SqlxErrorReport`] exists because `sqlx::Error::Database` embeds its
//! cause in its own `Display` *and* exposes it through `source()`, so
//! `ErrorReport`'s source walk printed the SQLite error twice.

use std::fmt::Display;

use crate::error::ErrorReport;

/// Result codes and their names, sorted by code so [`sqlite_code_name`] can
/// binary-search. Generated from the bundled `sqlite3.h`: every primary
/// `#define SQLITE_<NAME> <n>` and every extended
/// `#define SQLITE_<NAME> (SQLITE_<PRIMARY> | (<n><<8))`.
const CODE_NAMES: &[(i32, &str)] = &[
    (0, "SQLITE_OK"),
    (1, "SQLITE_ERROR"),
    (2, "SQLITE_INTERNAL"),
    (3, "SQLITE_PERM"),
    (4, "SQLITE_ABORT"),
    (5, "SQLITE_BUSY"),
    (6, "SQLITE_LOCKED"),
    (7, "SQLITE_NOMEM"),
    (8, "SQLITE_READONLY"),
    (9, "SQLITE_INTERRUPT"),
    (10, "SQLITE_IOERR"),
    (11, "SQLITE_CORRUPT"),
    (12, "SQLITE_NOTFOUND"),
    (13, "SQLITE_FULL"),
    (14, "SQLITE_CANTOPEN"),
    (15, "SQLITE_PROTOCOL"),
    (16, "SQLITE_EMPTY"),
    (17, "SQLITE_SCHEMA"),
    (18, "SQLITE_TOOBIG"),
    (19, "SQLITE_CONSTRAINT"),
    (20, "SQLITE_MISMATCH"),
    (21, "SQLITE_MISUSE"),
    (22, "SQLITE_NOLFS"),
    (23, "SQLITE_AUTH"),
    (24, "SQLITE_FORMAT"),
    (25, "SQLITE_RANGE"),
    (26, "SQLITE_NOTADB"),
    (27, "SQLITE_NOTICE"),
    (28, "SQLITE_WARNING"),
    (100, "SQLITE_ROW"),
    (101, "SQLITE_DONE"),
    (256, "SQLITE_OK_LOAD_PERMANENTLY"),
    (257, "SQLITE_ERROR_MISSING_COLLSEQ"),
    (261, "SQLITE_BUSY_RECOVERY"),
    (262, "SQLITE_LOCKED_SHAREDCACHE"),
    (264, "SQLITE_READONLY_RECOVERY"),
    (266, "SQLITE_IOERR_READ"),
    (267, "SQLITE_CORRUPT_VTAB"),
    (270, "SQLITE_CANTOPEN_NOTEMPDIR"),
    (275, "SQLITE_CONSTRAINT_CHECK"),
    (279, "SQLITE_AUTH_USER"),
    (283, "SQLITE_NOTICE_RECOVER_WAL"),
    (284, "SQLITE_WARNING_AUTOINDEX"),
    (512, "SQLITE_OK_SYMLINK"),
    (513, "SQLITE_ERROR_RETRY"),
    (516, "SQLITE_ABORT_ROLLBACK"),
    (517, "SQLITE_BUSY_SNAPSHOT"),
    (518, "SQLITE_LOCKED_VTAB"),
    (520, "SQLITE_READONLY_CANTLOCK"),
    (522, "SQLITE_IOERR_SHORT_READ"),
    (523, "SQLITE_CORRUPT_SEQUENCE"),
    (526, "SQLITE_CANTOPEN_ISDIR"),
    (531, "SQLITE_CONSTRAINT_COMMITHOOK"),
    (539, "SQLITE_NOTICE_RECOVER_ROLLBACK"),
    (769, "SQLITE_ERROR_SNAPSHOT"),
    (773, "SQLITE_BUSY_TIMEOUT"),
    (776, "SQLITE_READONLY_ROLLBACK"),
    (778, "SQLITE_IOERR_WRITE"),
    (779, "SQLITE_CORRUPT_INDEX"),
    (782, "SQLITE_CANTOPEN_FULLPATH"),
    (787, "SQLITE_CONSTRAINT_FOREIGNKEY"),
    (795, "SQLITE_NOTICE_RBU"),
    (1025, "SQLITE_ERROR_RESERVESIZE"),
    (1032, "SQLITE_READONLY_DBMOVED"),
    (1034, "SQLITE_IOERR_FSYNC"),
    (1038, "SQLITE_CANTOPEN_CONVPATH"),
    (1043, "SQLITE_CONSTRAINT_FUNCTION"),
    (1281, "SQLITE_ERROR_KEY"),
    (1288, "SQLITE_READONLY_CANTINIT"),
    (1290, "SQLITE_IOERR_DIR_FSYNC"),
    (1294, "SQLITE_CANTOPEN_DIRTYWAL"),
    (1299, "SQLITE_CONSTRAINT_NOTNULL"),
    (1537, "SQLITE_ERROR_UNABLE"),
    (1544, "SQLITE_READONLY_DIRECTORY"),
    (1546, "SQLITE_IOERR_TRUNCATE"),
    (1550, "SQLITE_CANTOPEN_SYMLINK"),
    (1555, "SQLITE_CONSTRAINT_PRIMARYKEY"),
    (1802, "SQLITE_IOERR_FSTAT"),
    (1811, "SQLITE_CONSTRAINT_TRIGGER"),
    (2058, "SQLITE_IOERR_UNLOCK"),
    (2067, "SQLITE_CONSTRAINT_UNIQUE"),
    (2314, "SQLITE_IOERR_RDLOCK"),
    (2323, "SQLITE_CONSTRAINT_VTAB"),
    (2570, "SQLITE_IOERR_DELETE"),
    (2579, "SQLITE_CONSTRAINT_ROWID"),
    (2826, "SQLITE_IOERR_BLOCKED"),
    (2835, "SQLITE_CONSTRAINT_PINNED"),
    (3082, "SQLITE_IOERR_NOMEM"),
    (3091, "SQLITE_CONSTRAINT_DATATYPE"),
    (3338, "SQLITE_IOERR_ACCESS"),
    (3594, "SQLITE_IOERR_CHECKRESERVEDLOCK"),
    (3850, "SQLITE_IOERR_LOCK"),
    (4106, "SQLITE_IOERR_CLOSE"),
    (4362, "SQLITE_IOERR_DIR_CLOSE"),
    (4618, "SQLITE_IOERR_SHMOPEN"),
    (4874, "SQLITE_IOERR_SHMSIZE"),
    (5130, "SQLITE_IOERR_SHMLOCK"),
    (5386, "SQLITE_IOERR_SHMMAP"),
    (5642, "SQLITE_IOERR_SEEK"),
    (5898, "SQLITE_IOERR_DELETE_NOENT"),
    (6154, "SQLITE_IOERR_MMAP"),
    (6410, "SQLITE_IOERR_GETTEMPPATH"),
    (6666, "SQLITE_IOERR_CONVPATH"),
    (6922, "SQLITE_IOERR_VNODE"),
    (7178, "SQLITE_IOERR_AUTH"),
    (7434, "SQLITE_IOERR_BEGIN_ATOMIC"),
    (7690, "SQLITE_IOERR_COMMIT_ATOMIC"),
    (7946, "SQLITE_IOERR_ROLLBACK_ATOMIC"),
    (8202, "SQLITE_IOERR_DATA"),
    (8458, "SQLITE_IOERR_CORRUPTFS"),
    (8714, "SQLITE_IOERR_IN_PAGE"),
    (8970, "SQLITE_IOERR_BADKEY"),
    (9226, "SQLITE_IOERR_CODEC"),
];

/// The symbolic name of a primary or extended SQLite result code, `None`
/// for a value the bundled `sqlite3.h` does not define.
pub(crate) fn sqlite_code_name(code: i32) -> Option<&'static str> {
    CODE_NAMES
        .binary_search_by_key(&code, |&(c, _)| c)
        .ok()
        .map(|i| CODE_NAMES[i].1)
}

/// Renders a `sqlx::Error` for a log line: the `Database` variant as one
/// `(code: <n> <NAME>) <message>` clause, any other variant through
/// [`ErrorReport`].
#[must_use]
pub(crate) struct SqlxErrorReport<'a>(pub(crate) &'a sqlx::Error);

impl Display for SqlxErrorReport<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sqlx::Error::Database(db) = self.0 else {
            return write!(f, "{}", ErrorReport(self.0));
        };

        // Same prefix sqlx's own `Display` uses, so the variant reads the
        // same in every log line.
        f.write_str("error returned from database: ")?;

        // sqlx's SQLite `code()` is the extended result code in decimal.
        match db.code().and_then(|c| c.parse::<i32>().ok()) {
            Some(code) => match sqlite_code_name(code) {
                Some(name) => write!(f, "(code: {code} {name}) {}", db.message()),
                None => write!(f, "(code: {code}) {}", db.message()),
            },
            None => write!(f, "{db}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_unique() {
        for (a, b) in CODE_NAMES.iter().zip(CODE_NAMES.iter().skip(1)) {
            assert!(a.0 < b.0, "{a:?} before {b:?}");
        }
    }

    #[test]
    fn extended_codes_carry_their_primary_code_in_the_low_byte() {
        for &(code, name) in CODE_NAMES {
            let primary = code & 0xff;
            let primary_name = sqlite_code_name(primary).expect("primary code present");
            assert!(
                name.starts_with(primary_name),
                "{name} ({code}) does not extend {primary_name} ({primary})"
            );
        }
    }

    /// `primary | (sub << 8)`, the shape of the `sqlite3.h` `#define`s.
    const fn extended(primary: i32, sub: i32) -> i32 {
        primary | (sub << 8)
    }

    #[test]
    fn names_known_codes() {
        assert_eq!(sqlite_code_name(0), Some("SQLITE_OK"));
        assert_eq!(sqlite_code_name(10), Some("SQLITE_IOERR"));
        assert_eq!(
            sqlite_code_name(extended(10, 25)),
            Some("SQLITE_IOERR_GETTEMPPATH")
        );
        assert_eq!(sqlite_code_name(6410), Some("SQLITE_IOERR_GETTEMPPATH"));
        assert_eq!(
            sqlite_code_name(extended(19, 8)),
            Some("SQLITE_CONSTRAINT_UNIQUE")
        );
        assert_eq!(sqlite_code_name(101), Some("SQLITE_DONE"));
    }

    #[test]
    fn rejects_unknown_codes() {
        assert_eq!(sqlite_code_name(-1), None);
        assert_eq!(sqlite_code_name(29), None);
        assert_eq!(sqlite_code_name(extended(10, 99)), None);
        assert_eq!(sqlite_code_name(i32::MAX), None);
    }

    #[tokio::test]
    async fn database_error_renders_once_with_its_name() {
        let (_dir, db) = crate::database::Database::temp().await;
        let err = sqlx::query("SELECT * FROM no_such_table")
            .execute(db.pool())
            .await
            .expect_err("missing table");

        let report = SqlxErrorReport(&err).to_string();
        assert_eq!(
            report,
            "error returned from database: (code: 1 SQLITE_ERROR) no such table: no_such_table"
        );
    }

    #[test]
    fn other_variants_fall_back_to_the_source_walk() {
        let err = sqlx::Error::RowNotFound;
        assert_eq!(
            SqlxErrorReport(&err).to_string(),
            ErrorReport(&err).to_string()
        );
    }
}
