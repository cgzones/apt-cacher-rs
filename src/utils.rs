use std::{
    ops::Deref,
    path::{Path, PathBuf},
};

use log::{debug, error};
use rand::{RngExt as _, distr::Alphanumeric, rngs::SmallRng};

use crate::Never;

/// Compile-time macro for creating a `NonZero` value, panicking if the value is zero.
#[macro_export]
macro_rules! nonzero {
    ($exp:expr) => {
        const {
            match ::std::num::NonZero::new($exp) {
                Some(v) => v,
                None => panic!("nonzero!() called with zero value"),
            }
        }
    };
}

/// Compile-time assertion macro.
#[macro_export]
macro_rules! static_assert {
    ($cond:expr) => {
        const _: () = assert!($cond);
    };
    ($cond:expr, $msg:expr) => {
        const _: () = assert!($cond, $msg);
    };
}

/// A temporary file-path guard that automatically deletes the underlying file when dropped.
pub(crate) struct TempPath {
    path: Option<PathBuf>,
}

impl TempPath {
    /// Defuse the temporary path guard, returning the underlying `PathBuf`.
    pub(crate) fn into_inner(mut self) -> PathBuf {
        std::mem::take(&mut self.path).expect("path has not been destructed yet")
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            tokio::task::spawn_blocking(move || {
                if let Err(err) = std::fs::remove_file(&path) {
                    error!(
                        "Failed to remove temporary file `{}`:  {err}",
                        path.display()
                    );
                } else {
                    debug!("Removed temporary file `{}`", path.display());
                }
            });
        }
    }
}

impl Deref for TempPath {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.path
            .as_deref()
            .expect("path has not been destructed yet")
    }
}

impl AsRef<Path> for TempPath {
    fn as_ref(&self) -> &Path {
        self.path
            .as_deref()
            .expect("path has not been destructed yet")
    }
}

/// Create a temporary file with a unique extension for the given path.
pub(crate) async fn tokio_tempfile(
    path: &Path,
    mode: u32,
) -> Result<(tokio::fs::File, TempPath), tokio::io::Error> {
    let mut rng: SmallRng = rand::make_rng();

    let mut buf = path.to_path_buf();

    let mut tries = 0;
    loop {
        const MAX_TRIES: u32 = 10;

        let s: String = (&mut rng)
            .sample_iter(Alphanumeric)
            .take(6)
            .map(char::from)
            .collect();

        assert!(
            buf.set_extension(s),
            "buf is non-empty so adding a new extension must succeed"
        );

        let _: Never = match tokio::fs::File::options()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(&buf)
            .await
        {
            Ok(file) => {
                return Ok((file, TempPath { path: Some(buf) }));
            }
            Err(err) if err.kind() == tokio::io::ErrorKind::AlreadyExists => {
                tries += 1;
                if tries > MAX_TRIES {
                    return Err(err);
                }
                assert!(
                    buf.set_extension(""),
                    "buf is non-empty so removing an existing extension must succeed"
                );
                continue;
            }
            Err(err) => return Err(err),
        };
    }
}
