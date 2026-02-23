use std::{
    net::{IpAddr, Ipv6Addr},
    num::NonZero,
    path::PathBuf,
    str::FromStr as _,
    time::Duration,
};

use log::{LevelFilter, debug, info, trace};
use sqlx::{
    ConnectOptions as _, Error, Executor as _, Pool, Sqlite, SqlitePool, query, query_as,
    sqlite::SqliteConnectOptions,
};

use crate::{
    config::DomainName,
    deb_mirror::{Mirror, OriginRef, mirror_cache_path_impl},
};

#[derive(Debug, Clone)]
pub(crate) struct Database {
    conn: Pool<Sqlite>,
}

#[derive(Clone, Debug)]
pub(crate) struct MirrorEntry {
    pub(crate) host: DomainName,
    /// Raw port from database. `0` means no explicit port; use `port()` to get `Option<NonZero<u16>>`.
    port: u16,
    pub(crate) path: String,
}

impl MirrorEntry {
    #[must_use]
    pub(crate) const fn port(&self) -> Option<NonZero<u16>> {
        NonZero::new(self.port)
    }

    #[must_use]
    pub(crate) fn cache_path(&self) -> PathBuf {
        mirror_cache_path_impl(&self.host, self.port(), &self.path)
    }
}

#[derive(Debug)]
pub(crate) struct MirrorStatEntry {
    pub(crate) host: DomainName,
    /// Raw port from database. `0` means no explicit port; use `port()` to get `Option<NonZero<u16>>`.
    port: u16,
    pub(crate) path: String,
    pub(crate) first_seen: i64,
    pub(crate) last_seen: i64,
    pub(crate) last_cleanup: i64,
    pub(crate) total_download_size: i64,
    pub(crate) total_delivery_size: i64,
}

impl MirrorStatEntry {
    #[must_use]
    pub(crate) const fn port(&self) -> Option<NonZero<u16>> {
        NonZero::new(self.port)
    }

    #[must_use]
    pub(crate) fn uri(&self) -> String {
        if self.port == 0 {
            format!("{}/{}", self.host, self.path)
        } else {
            format!("{}:{}/{}", self.host, self.port, self.path)
        }
    }

    #[must_use]
    pub(crate) fn cache_path(&self) -> PathBuf {
        mirror_cache_path_impl(&self.host, self.port(), &self.path)
    }
}

#[derive(Debug)]
pub(crate) struct OriginEntry {
    pub(crate) host: DomainName,
    /// Raw port from database. `0` means no explicit port; use `port()` to get `Option<NonZero<u16>>`.
    port: u16,
    pub(crate) mirror_path: String,
    pub(crate) distribution: String,
    pub(crate) component: String,
    pub(crate) architecture: String,
    pub(crate) last_seen: i64,
}

impl OriginEntry {
    #[must_use]
    pub(crate) const fn port(&self) -> Option<NonZero<u16>> {
        NonZero::new(self.port)
    }

    #[must_use]
    pub(crate) fn mirror_uri(&self) -> String {
        if self.port == 0 {
            format!("{}/{}", self.host, self.mirror_path)
        } else {
            format!("{}:{}/{}", self.host, self.port, self.mirror_path)
        }
    }
}

impl Database {
    pub(crate) async fn connect(
        path: &std::path::Path,
        slow_timeout: Duration,
    ) -> Result<Self, Error> {
        let url = format!("sqlite://{}", path.display());

        info!("Opening database `{url}`...");
        debug!("Using slow timeout of {slow_timeout:?}");

        let opts = SqliteConnectOptions::from_str(&url)?
            .create_if_missing(true)
            .log_statements(LevelFilter::Trace)
            .log_slow_statements(LevelFilter::Warn, slow_timeout);
        let conn = SqlitePool::connect_with(opts).await?;

        Ok(Self { conn })
    }

    pub(crate) async fn init_tables(&self) -> Result<(), Error> {
        trace!("Initializing database tables...");

        self.conn
            .execute(
                r"
                CREATE TABLE IF NOT EXISTS mirrors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host TEXT NOT NULL,
                    path TEXT NOT NULL,
                    first_seen INTEGER NOT NULL DEFAULT (unixepoch(CURRENT_TIMESTAMP)),
                    last_seen INTEGER NOT NULL DEFAULT (unixepoch(CURRENT_TIMESTAMP)),
                    last_cleanup INTEGER NOT NULL DEFAULT 0,
                    CONSTRAINT first UNIQUE (host, path)
                ) STRICT;
                ",
            )
            .await?;

        self.conn
            .execute(
                r"
                CREATE TABLE IF NOT EXISTS origins (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mirror_id INTEGER NOT NULL,
                        distribution TEXT NOT NULL,
                        component TEXT NOT NULL,
                        architecture TEXT NOT NULL,
                        first_seen INTEGER NOT NULL DEFAULT (unixepoch(CURRENT_TIMESTAMP)),
                        last_seen INTEGER NOT NULL DEFAULT (unixepoch(CURRENT_TIMESTAMP)),
                CONSTRAINT first UNIQUE (mirror_id, distribution, component, architecture)
                ) STRICT;
                ",
            )
            .await?;

        self.conn
            .execute(
                r"
                CREATE TABLE IF NOT EXISTS downloads (
                        mirror_id INTEGER NOT NULL,
                        debname TEXT NOT NULL,
                        size INTEGER NOT NULL,
                        duration INTEGER NOT NULL,
                        client_ip BLOB NOT NULL,
                        timestamp INTEGER NOT NULL DEFAULT (unixepoch(CURRENT_TIMESTAMP))
                ) STRICT;
                ",
            )
            .await?;

        self.conn
            .execute(
                r"
                CREATE TABLE IF NOT EXISTS deliveries (
                        mirror_id INTEGER NOT NULL,
                        debname TEXT NOT NULL,
                        size INTEGER NOT NULL,
                        duration INTEGER NOT NULL,
                        partial INTEGER NOT NULL,
                        client_ip BLOB NOT NULL,
                        timestamp INTEGER NOT NULL DEFAULT (unixepoch(CURRENT_TIMESTAMP))
                ) STRICT;
                ",
            )
            .await?;

        trace!("Performing database migrations...");

        sqlx::migrate!().run(&self.conn).await?;

        Ok(())
    }

    pub(crate) async fn add_origin(&self, origin: &OriginRef<'_>) -> Result<(), Error> {
        let port = origin.mirror.port.map_or(0, std::num::NonZero::get);

        query!(
            r"
                INSERT INTO mirrors_v2
                (host, port, path)
                VALUES
                (?, ?, ?)
                ON CONFLICT
                DO UPDATE SET last_seen = unixepoch(CURRENT_TIMESTAMP);

                INSERT INTO origins
                (mirror_id, distribution, component, architecture)
                VALUES
                ((SELECT id FROM mirrors_v2 WHERE host = ? AND port = ? AND path = ?), ?, ?, ?)
                ON CONFLICT (mirror_id, distribution, component, architecture)
                DO UPDATE SET last_seen = unixepoch(CURRENT_TIMESTAMP);
        ",
            origin.mirror.host,
            port,
            origin.mirror.path,
            origin.mirror.host,
            port,
            origin.mirror.path,
            origin.distribution,
            origin.component,
            origin.architecture
        )
        .execute(&self.conn)
        .await?;

        Ok(())
    }

    pub(crate) async fn get_mirrors(&self) -> Result<Vec<MirrorEntry>, Error> {
        query_as!(
            MirrorEntry,
            r#"
              SELECT host, port AS "port: u16", path
              FROM mirrors_v2;
        "#,
        )
        .fetch_all(&self.conn)
        .await
    }

    pub(crate) async fn get_mirrors_with_stats(&self) -> Result<Vec<MirrorStatEntry>, Error> {
        query_as!(MirrorStatEntry,
            r#"
            SELECT
                mirrors_v2.host,
                mirrors_v2.port AS "port: u16",
                mirrors_v2.path,
                mirrors_v2.first_seen,
                mirrors_v2.last_seen,
                mirrors_v2.last_cleanup,
                COALESCE(downloads.total_size, 0) AS "total_download_size: i64",
                COALESCE(deliveries.total_size, 0) AS "total_delivery_size: i64"
            FROM mirrors_v2
            LEFT JOIN
                (SELECT mirror_id, SUM(size) AS total_size FROM downloads GROUP BY mirror_id) AS downloads
            ON mirrors_v2.id == downloads.mirror_id
            LEFT JOIN
                (SELECT mirror_id, SUM(size) AS total_size FROM deliveries GROUP BY mirror_id) AS deliveries
            ON mirrors_v2.id == deliveries.mirror_id
            ;
        "#).fetch_all(&self.conn).await
    }

    pub(crate) async fn get_origins(&self) -> Result<Vec<OriginEntry>, Error> {
        query_as!(
            OriginEntry,
            r#"
              SELECT
                mirrors_v2.host,
                mirrors_v2.port AS "port: u16",
                mirrors_v2.path AS mirror_path,
                origins.distribution,
                origins.component,
                origins.architecture,
                origins.last_seen
              FROM origins
              JOIN mirrors_v2
              WHERE mirrors_v2.id = origins.mirror_id;
        "#,
        )
        .fetch_all(&self.conn)
        .await
    }

    pub(crate) async fn get_origins_by_mirror(
        &self,
        host: &str,
        port: Option<NonZero<u16>>,
        path: &str,
    ) -> Result<Vec<OriginEntry>, Error> {
        let port = port.map_or(0, std::num::NonZero::get);

        query_as!(OriginEntry,
            r#"
              SELECT
                mirrors_v2.host,
                mirrors_v2.port AS "port: u16",
                mirrors_v2.path AS mirror_path,
                origins.distribution,
                origins.component,
                origins.architecture,
                origins.last_seen
              FROM origins
              JOIN mirrors_v2
              WHERE mirrors_v2.host = ? AND mirrors_v2.port = ? AND mirrors_v2.path = ? AND mirrors_v2.id = origins.mirror_id;
        "#, host, port, path
        )
        .fetch_all(&self.conn).await
    }

    pub(crate) async fn mirror_cleanup(&self, mirror: &Mirror) -> Result<(), Error> {
        let port = mirror.port.map_or(0, std::num::NonZero::get);

        query!(
            r"
                UPDATE mirrors_v2
                SET last_cleanup = unixepoch(CURRENT_TIMESTAMP)
                WHERE host = ? AND port = ? AND path = ?;
        ",
            mirror.host,
            port,
            mirror.path
        )
        .execute(&self.conn)
        .await?;

        Ok(())
    }

    pub(crate) async fn get_clients(&self) -> Result<Vec<IpAddr>, Error> {
        struct IpFmt {
            client_ip: Vec<u8>,
        }

        let ips = query_as!(
            IpFmt,
            r"
                SELECT client_ip FROM deliveries GROUP BY client_ip;
            "
        )
        .fetch_all(&self.conn)
        .await?;

        // TODO: check during cleanup that all client_ip BLOB entries are valid?
        Ok(ips
            .into_iter()
            .filter_map(|s| {
                let octets: [u8; 16] = s.client_ip.try_into().ok()?;
                let ip: Ipv6Addr = octets.into();
                Some(ip.to_canonical())
            })
            .collect())
    }

    pub(crate) async fn register_download(
        &self,
        mirror: &Mirror,
        debname: &str,
        size: u64,
        duration: Duration,
        client: IpAddr,
    ) -> Result<(), Error> {
        let size = i64::try_from(size).map_err(|err| Error::TypeNotFound {
            type_name: err.to_string(),
        })?;
        let duration = i64::try_from(duration.as_millis()).map_err(|err| Error::TypeNotFound {
            type_name: err.to_string(),
        })?;
        let client = match client {
            IpAddr::V4(ipv4) => ipv4.to_ipv6_mapped(),
            IpAddr::V6(ipv6) => ipv6,
        };
        let client: &[u8] = &client.octets();

        let port = mirror.port.map_or(0, std::num::NonZero::get);

        query!(
            r"
                INSERT INTO mirrors_v2
                (host, port, path)
                VALUES
                (?, ?, ?)
                ON CONFLICT
                DO UPDATE SET last_seen = unixepoch(CURRENT_TIMESTAMP);

                INSERT INTO downloads
                (mirror_id, debname, size, duration, client_ip)
                VALUES
                ((SELECT id FROM mirrors_v2 WHERE host = ? AND port = ? AND path = ?), ?, ?, ?, ?);
        ",
            mirror.host,
            port,
            mirror.path,
            mirror.host,
            port,
            mirror.path,
            debname,
            size,
            duration,
            client
        )
        .execute(&self.conn)
        .await?;

        Ok(())
    }

    pub(crate) async fn register_delivery(
        &self,
        mirror: &Mirror,
        debname: &str,
        size: u64,
        duration: Duration,
        partial: bool,
        client: IpAddr,
    ) -> Result<(), Error> {
        let size = i64::try_from(size).map_err(|err| Error::TypeNotFound {
            type_name: err.to_string(),
        })?;
        let duration = i64::try_from(duration.as_millis()).map_err(|err| Error::TypeNotFound {
            type_name: err.to_string(),
        })?;
        let partial = u8::from(partial);
        let client = match client {
            IpAddr::V4(ipv4) => ipv4.to_ipv6_mapped(),
            IpAddr::V6(ipv6) => ipv6,
        };
        let client: &[u8] = &client.octets();

        let port = mirror.port.map_or(0, std::num::NonZero::get);

        query!(
            r"
                INSERT INTO mirrors_v2
                (host, port, path)
                VALUES
                (?, ?, ?)
                ON CONFLICT
                DO UPDATE SET last_seen = unixepoch(CURRENT_TIMESTAMP);

                INSERT INTO deliveries
                (mirror_id, debname, size, duration, partial, client_ip)
                VALUES
                ((SELECT id FROM mirrors_v2 WHERE host = ? AND port = ? AND path = ?), ?, ?, ?, ?, ?);
            ",
            mirror.host,
            port,
            mirror.path,
            mirror.host,
            port,
            mirror.path,
            debname,
            size,
            duration,
            partial,
            client
        )
        .execute(&self.conn)
        .await?;

        Ok(())
    }

    pub(crate) async fn delete_usage_logs(&self, keep_date: Duration) -> Result<(), Error> {
        let keep_epoch = i64::try_from(keep_date.as_secs()).map_err(|err| Error::TypeNotFound {
            type_name: err.to_string(),
        })?;
        query!(
            r"
                DELETE FROM downloads
                WHERE timestamp < ?;
                DELETE FROM deliveries
                WHERE timestamp < ?;
            ",
            keep_epoch,
            keep_epoch
        )
        .execute(&self.conn)
        .await?;

        Ok(())
    }
}
