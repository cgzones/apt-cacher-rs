use std::{
    net::{IpAddr, Ipv6Addr},
    str::FromStr,
    time::Duration,
};

use log::{LevelFilter, debug, info, trace};
use sqlx::{
    ConnectOptions, Error, Executor, Pool, Sqlite, SqlitePool, query, query_as,
    sqlite::SqliteConnectOptions,
};

use crate::{
    config::DomainName,
    deb_mirror::{Mirror, OriginRef},
};

#[derive(Debug, Clone)]
pub(crate) struct Database {
    conn: Pool<Sqlite>,
}

#[derive(Debug)]
pub(crate) struct MirrorEntry {
    pub(crate) host: DomainName,
    pub(crate) path: String,
    #[expect(unused)]
    pub(crate) first_seen: i64,
    #[expect(unused)]
    pub(crate) last_seen: i64,
    #[expect(unused)]
    pub(crate) last_cleanup: i64,
}

#[derive(Debug)]
pub(crate) struct MirrorStatEntry {
    pub(crate) host: DomainName,
    pub(crate) path: String,
    pub(crate) first_seen: i64,
    pub(crate) last_seen: i64,
    pub(crate) last_cleanup: i64,
    pub(crate) total_download_size: i64,
    pub(crate) total_delivery_size: i64,
}

#[derive(Debug)]
pub(crate) struct OriginEntry {
    pub(crate) host: DomainName,
    pub(crate) mirror_path: String,
    pub(crate) distribution: String,
    pub(crate) component: String,
    pub(crate) architecture: String,
    pub(crate) last_seen: i64,
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

        Ok(())
    }

    async fn add_mirror(&self, mirror: &Mirror) -> Result<(), Error> {
        query!(
            r"
                INSERT INTO mirrors
                (host, path)
                VALUES
                (?, ?)
                ON CONFLICT
                DO UPDATE SET last_seen = unixepoch(CURRENT_TIMESTAMP);
        ",
            mirror.host,
            mirror.path
        )
        .execute(&self.conn)
        .await?;

        Ok(())
    }

    pub(crate) async fn add_origin(&self, origin: &OriginRef<'_>) -> Result<(), Error> {
        self.add_mirror(origin.mirror).await?;

        query!(
            r"
                INSERT INTO origins
                (mirror_id, distribution, component, architecture)
                VALUES
                ((SELECT id FROM mirrors WHERE host = ? AND path = ?), ?, ?, ?)
                ON CONFLICT (mirror_id, distribution, component, architecture)
                DO UPDATE SET last_seen = unixepoch(CURRENT_TIMESTAMP);
        ",
            origin.mirror.host,
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
            r"
              SELECT host, path, first_seen, last_seen, last_cleanup FROM mirrors;
        ",
        )
        .fetch_all(&self.conn)
        .await
    }

    pub(crate) async fn get_mirrors_with_stats(&self) -> Result<Vec<MirrorStatEntry>, Error> {
        query_as!(MirrorStatEntry,
            r#"
            SELECT
                mirrors.host,
                mirrors.path,
                mirrors.first_seen,
                mirrors.last_seen,
                mirrors.last_cleanup,
                COALESCE(downloads.total_size, 0) AS "total_download_size: i64",
                COALESCE(deliveries.total_size, 0) AS "total_delivery_size: i64"
            FROM mirrors
            LEFT JOIN
                (SELECT mirror_id, SUM(size) AS total_size FROM downloads GROUP BY mirror_id) AS downloads
            ON mirrors.id == downloads.mirror_id
            LEFT JOIN
                (SELECT mirror_id, SUM(size) AS total_size FROM deliveries GROUP BY mirror_id) AS deliveries
            ON mirrors.id == deliveries.mirror_id
            ;
        "#).fetch_all(&self.conn).await
    }

    pub(crate) async fn get_origins(&self) -> Result<Vec<OriginEntry>, Error> {
        query_as!(
            OriginEntry,
            r"
              SELECT mirrors.host, mirrors.path AS mirror_path, origins.distribution, origins.component, origins.architecture, origins.last_seen
              FROM origins
              JOIN mirrors
              WHERE mirrors.id = origins.mirror_id;
        ",
        )
        .fetch_all(&self.conn)
        .await
    }

    pub(crate) async fn get_origins_by_mirror(
        &self,
        host: &str,
        path: &str,
    ) -> Result<Vec<OriginEntry>, Error> {
        query_as!(OriginEntry,
            r"
              SELECT mirrors.host, mirrors.path AS mirror_path, origins.distribution, origins.component, origins.architecture, origins.last_seen
              FROM origins
              JOIN mirrors
              WHERE mirrors.host = ? AND mirrors.path = ? AND mirrors.id = origins.mirror_id;
        ", host, path
        )
        .fetch_all(&self.conn).await
    }

    pub(crate) async fn mirror_cleanup(&self, mirror: &Mirror) -> Result<(), Error> {
        query!(
            r"
                UPDATE mirrors
                SET last_cleanup = unixepoch(CURRENT_TIMESTAMP)
                WHERE host = ? AND path = ?;
        ",
            mirror.host,
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

        self.add_mirror(mirror).await?;

        query!(
            r"
                INSERT INTO downloads
                (mirror_id, debname, size, duration, client_ip)
                VALUES
                ((SELECT id FROM mirrors WHERE host = ? AND path = ?), ?, ?, ?, ?);
        ",
            mirror.host,
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

    pub(crate) async fn register_deliviery(
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

        self.add_mirror(mirror).await?;

        query!(
            r"
                INSERT INTO deliveries
                (mirror_id, debname, size, duration, partial, client_ip)
                VALUES
                ((SELECT id FROM mirrors WHERE host = ? AND path = ?), ?, ?, ?, ?, ?);
            ",
            mirror.host,
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
