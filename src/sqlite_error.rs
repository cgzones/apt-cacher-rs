//! Names for SQLite result codes and a log renderer for `sqlx::Error`.
//!
//! SQLite has no API that turns a result code back into its symbolic name:
//! `sqlite3_errstr()` is indexed by the primary code (`code & 0xff`), so for
//! an extended code it returns the same generic text the error already
//! carries (`disk I/O error` for `SQLITE_IOERR_GETTEMPPATH`). The name is
//! what an operator needs, so [`CODE_NAMES`] names the result codes from the
//! bundled SQLite bindings. The numeric values are public ABI and never
//! renumbered; a bump of the bundled SQLite can only append entries.
//!
//! [`SqlxErrorReport`] exists because `sqlx::Error::Database` embeds its
//! cause in its own `Display` *and* exposes it through `source()`, so
//! `ErrorReport`'s source walk printed the SQLite error twice. Every log
//! line that renders a `sqlx::Error` goes through it, and so does the
//! `Display` of an error enum wrapping one (`MainLoopError::Database`,
//! `CacheScanError::Sqlx`), which keeps the `sqlx::Error` off `source()`.

use std::fmt::Display;

use crate::error::ErrorReport;

macro_rules! code_names {
    ($($code:ident),* $(,)?) => {
        &[$((libsqlite3_sys::$code, stringify!($code))),*]
    };
}

/// Result codes and their names, sorted by code so [`sqlite_code_name`] can
/// binary-search. Values come from the bundled SQLite bindings; each primary
/// and extended result-code name is listed only once.
const CODE_NAMES: &[(i32, &str)] = code_names![
    SQLITE_OK,
    SQLITE_ERROR,
    SQLITE_INTERNAL,
    SQLITE_PERM,
    SQLITE_ABORT,
    SQLITE_BUSY,
    SQLITE_LOCKED,
    SQLITE_NOMEM,
    SQLITE_READONLY,
    SQLITE_INTERRUPT,
    SQLITE_IOERR,
    SQLITE_CORRUPT,
    SQLITE_NOTFOUND,
    SQLITE_FULL,
    SQLITE_CANTOPEN,
    SQLITE_PROTOCOL,
    SQLITE_EMPTY,
    SQLITE_SCHEMA,
    SQLITE_TOOBIG,
    SQLITE_CONSTRAINT,
    SQLITE_MISMATCH,
    SQLITE_MISUSE,
    SQLITE_NOLFS,
    SQLITE_AUTH,
    SQLITE_FORMAT,
    SQLITE_RANGE,
    SQLITE_NOTADB,
    SQLITE_NOTICE,
    SQLITE_WARNING,
    SQLITE_ROW,
    SQLITE_DONE,
    SQLITE_OK_LOAD_PERMANENTLY,
    SQLITE_ERROR_MISSING_COLLSEQ,
    SQLITE_BUSY_RECOVERY,
    SQLITE_LOCKED_SHAREDCACHE,
    SQLITE_READONLY_RECOVERY,
    SQLITE_IOERR_READ,
    SQLITE_CORRUPT_VTAB,
    SQLITE_CANTOPEN_NOTEMPDIR,
    SQLITE_CONSTRAINT_CHECK,
    SQLITE_AUTH_USER,
    SQLITE_NOTICE_RECOVER_WAL,
    SQLITE_WARNING_AUTOINDEX,
    SQLITE_OK_SYMLINK,
    SQLITE_ERROR_RETRY,
    SQLITE_ABORT_ROLLBACK,
    SQLITE_BUSY_SNAPSHOT,
    SQLITE_LOCKED_VTAB,
    SQLITE_READONLY_CANTLOCK,
    SQLITE_IOERR_SHORT_READ,
    SQLITE_CORRUPT_SEQUENCE,
    SQLITE_CANTOPEN_ISDIR,
    SQLITE_CONSTRAINT_COMMITHOOK,
    SQLITE_NOTICE_RECOVER_ROLLBACK,
    SQLITE_ERROR_SNAPSHOT,
    SQLITE_BUSY_TIMEOUT,
    SQLITE_READONLY_ROLLBACK,
    SQLITE_IOERR_WRITE,
    SQLITE_CORRUPT_INDEX,
    SQLITE_CANTOPEN_FULLPATH,
    SQLITE_CONSTRAINT_FOREIGNKEY,
    SQLITE_NOTICE_RBU,
    SQLITE_ERROR_RESERVESIZE,
    SQLITE_READONLY_DBMOVED,
    SQLITE_IOERR_FSYNC,
    SQLITE_CANTOPEN_CONVPATH,
    SQLITE_CONSTRAINT_FUNCTION,
    SQLITE_ERROR_KEY,
    SQLITE_READONLY_CANTINIT,
    SQLITE_IOERR_DIR_FSYNC,
    SQLITE_CANTOPEN_DIRTYWAL,
    SQLITE_CONSTRAINT_NOTNULL,
    SQLITE_ERROR_UNABLE,
    SQLITE_READONLY_DIRECTORY,
    SQLITE_IOERR_TRUNCATE,
    SQLITE_CANTOPEN_SYMLINK,
    SQLITE_CONSTRAINT_PRIMARYKEY,
    SQLITE_IOERR_FSTAT,
    SQLITE_CONSTRAINT_TRIGGER,
    SQLITE_IOERR_UNLOCK,
    SQLITE_CONSTRAINT_UNIQUE,
    SQLITE_IOERR_RDLOCK,
    SQLITE_CONSTRAINT_VTAB,
    SQLITE_IOERR_DELETE,
    SQLITE_CONSTRAINT_ROWID,
    SQLITE_IOERR_BLOCKED,
    SQLITE_CONSTRAINT_PINNED,
    SQLITE_IOERR_NOMEM,
    SQLITE_CONSTRAINT_DATATYPE,
    SQLITE_IOERR_ACCESS,
    SQLITE_IOERR_CHECKRESERVEDLOCK,
    SQLITE_IOERR_LOCK,
    SQLITE_IOERR_CLOSE,
    SQLITE_IOERR_DIR_CLOSE,
    SQLITE_IOERR_SHMOPEN,
    SQLITE_IOERR_SHMSIZE,
    SQLITE_IOERR_SHMLOCK,
    SQLITE_IOERR_SHMMAP,
    SQLITE_IOERR_SEEK,
    SQLITE_IOERR_DELETE_NOENT,
    SQLITE_IOERR_MMAP,
    SQLITE_IOERR_GETTEMPPATH,
    SQLITE_IOERR_CONVPATH,
    SQLITE_IOERR_VNODE,
    SQLITE_IOERR_AUTH,
    SQLITE_IOERR_BEGIN_ATOMIC,
    SQLITE_IOERR_COMMIT_ATOMIC,
    SQLITE_IOERR_ROLLBACK_ATOMIC,
    SQLITE_IOERR_DATA,
    SQLITE_IOERR_CORRUPTFS,
    SQLITE_IOERR_IN_PAGE,
    SQLITE_IOERR_BADKEY,
    SQLITE_IOERR_CODEC,
];

/// The symbolic name of a primary or extended SQLite result code, `None`
/// for a value the bundled `sqlite3.h` does not define.
fn sqlite_code_name(code: i32) -> Option<&'static str> {
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
        use sqlx::Connection as _;
        let mut db = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("memory database");
        let err = sqlx::query("SELECT * FROM no_such_table")
            .execute(&mut db)
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
