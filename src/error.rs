use std::fmt::Display;

use coarsetime::Duration;

use crate::rate_checked_body::InsufficientRate;
use crate::{ChannelBodyError, ClientInfo, ContentLength};
use crate::{deb_mirror::Mirror, humanfmt::HumanFmt};

#[derive(Clone, Debug)]
pub(crate) struct MirrorDownloadRate {
    pub(crate) download_rate_err: InsufficientRate,
    pub(crate) mirror: Mirror,
    pub(crate) debname: String,
    pub(crate) client: ClientInfo,
}

#[derive(Debug)]
pub(crate) enum ProxyCacheError {
    Io(std::io::Error),
    Hyper(hyper::Error),
    Sqlx(sqlx::Error),
    SystemTime(std::time::SystemTimeError),
    ClientDownloadRate {
        error: InsufficientRate,
        client: ClientInfo,
    },
    MirrorDownloadRate(MirrorDownloadRate),
    Memfd(memfd::Error),
    ContentTooLarge {
        announced: ContentLength,
        received: u64,
    },
}

impl std::fmt::Display for ProxyCacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{}", ErrorReport(e)),
            Self::Hyper(e) => write!(f, "{}", ErrorReport(e)),
            Self::Sqlx(e) => e.fmt(f),
            Self::SystemTime(e) => e.fmt(f),
            Self::ClientDownloadRate { error, client } => error.display(client).fmt(f),
            Self::MirrorDownloadRate(MirrorDownloadRate {
                download_rate_err,
                mirror,
                debname,
                client,
            }) => {
                write!(
                    f,
                    "Timeout occurred for mirror {} downloading file {} for client {client} after a download rate of {} [< {}] for the last {} seconds",
                    mirror,
                    debname,
                    HumanFmt::Rate(
                        download_rate_err.transferred as u64,
                        Duration::from_secs(download_rate_err.timeframe.get() as u64)
                    ),
                    HumanFmt::Rate(
                        download_rate_err.min_rate.get() as u64,
                        Duration::from_secs(1)
                    ),
                    download_rate_err.timeframe,
                )
            }
            Self::Memfd(e) => write!(f, "{}", ErrorReport(e)),
            Self::ContentTooLarge {
                announced,
                received,
            } => {
                write!(
                    f,
                    "Received data of {received} bytes larger than announced {announced}"
                )
            }
        }
    }
}

impl std::error::Error for ProxyCacheError {}

impl From<std::io::Error> for ProxyCacheError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<hyper::Error> for ProxyCacheError {
    fn from(value: hyper::Error) -> Self {
        Self::Hyper(value)
    }
}

impl From<sqlx::Error> for ProxyCacheError {
    fn from(value: sqlx::Error) -> Self {
        Self::Sqlx(value)
    }
}

impl From<std::time::SystemTimeError> for ProxyCacheError {
    fn from(value: std::time::SystemTimeError) -> Self {
        Self::SystemTime(value)
    }
}

impl From<ChannelBodyError> for ProxyCacheError {
    fn from(value: ChannelBodyError) -> Self {
        match value {
            ChannelBodyError::MirrorDownloadRate(mdr) => Self::MirrorDownloadRate(mdr),
        }
    }
}

#[must_use]
pub(crate) struct ErrorReport<'a, E>(pub(crate) &'a E)
where
    E: std::error::Error;

impl<E> Display for ErrorReport<'_, E>
where
    E: std::error::Error,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)?;

        let mut cause: &dyn std::error::Error = self.0;

        while let Some(c) = cause.source() {
            write!(f, ":  {c}")?;
            cause = c;
        }

        Ok(())
    }
}

#[cfg(feature = "sendfile")]
pub(crate) fn errno_to_io_error(errno: nix::errno::Errno, msg: &'static str) -> std::io::Error {
    #[derive(Debug)]
    struct ErrnoIoError {
        msg: &'static str,
        source: std::io::Error,
    }
    #[cfg(feature = "sendfile")]
    impl Display for ErrnoIoError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}: {}", self.msg, self.source)
        }
    }
    #[cfg(feature = "sendfile")]
    impl std::error::Error for ErrnoIoError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.source)
        }
    }

    let err = std::io::Error::from_raw_os_error(errno as i32);
    let kind = err.kind();
    std::io::Error::new(kind, ErrnoIoError { msg, source: err })
}
