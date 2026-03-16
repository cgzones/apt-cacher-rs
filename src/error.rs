use std::fmt::Display;
use std::net::IpAddr;

use coarsetime::Duration;

use crate::rate_checked_body::InsufficientRate;
use crate::{ChannelBodyError, ContentLength};
use crate::{deb_mirror::Mirror, humanfmt::HumanFmt};

#[derive(Clone, Debug)]
pub(crate) struct MirrorDownloadRate {
    pub(crate) download_rate_err: InsufficientRate,
    pub(crate) mirror: Mirror,
    pub(crate) debname: String,
    pub(crate) client_ip: IpAddr,
}

#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum ProxyCacheError {
    Io(std::io::Error),
    Hyper(hyper::Error),
    Sqlx(sqlx::Error),
    SystemTime(std::time::SystemTimeError),
    ClientDownloadRate {
        error: InsufficientRate,
        client_ip: IpAddr,
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
            Self::Io(e) => e.fmt(f),
            Self::Hyper(e) => write!(f, "{}", ErrorReport::new(e)),
            Self::Sqlx(e) => e.fmt(f),
            Self::SystemTime(e) => e.fmt(f),
            Self::ClientDownloadRate { error, client_ip } => {
                write!(
                    f,
                    "Timeout occurred for client {} after a download rate of {} [< {}] for the last {} seconds",
                    client_ip.to_canonical(),
                    HumanFmt::Rate(
                        error.transferred as u64,
                        Duration::from_secs(error.timeframe.get() as u64)
                    ),
                    HumanFmt::Rate(error.min_rate.get() as u64, Duration::from_secs(1)),
                    error.timeframe,
                )
            }
            Self::MirrorDownloadRate(MirrorDownloadRate {
                download_rate_err,
                mirror,
                debname,
                client_ip,
            }) => {
                write!(
                    f,
                    "Timeout occurred for mirror {} downloading file {} for client {} after a download rate of {} [< {}] for the last {} seconds",
                    mirror,
                    debname,
                    client_ip.to_canonical(),
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
            Self::Memfd(e) => e.fmt(f),
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
pub(crate) struct ErrorReport<'a, E>
where
    E: std::error::Error,
{
    err: &'a E,
}

impl<'a, E> ErrorReport<'a, E>
where
    E: std::error::Error,
{
    pub(crate) const fn new(err: &'a E) -> Self {
        Self { err }
    }
}

impl<E> Display for ErrorReport<'_, E>
where
    E: std::error::Error,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.err)?;

        let mut cause: &dyn std::error::Error = self.err;

        loop {
            if let Some(c) = cause.source() {
                write!(f, ":  {c}")?;
                cause = c;
                continue;
            }

            break;
        }

        Ok(())
    }
}
