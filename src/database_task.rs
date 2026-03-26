use core::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use coarsetime::Duration;
use log::{debug, error, info};

use crate::{
    database::Database,
    deb_mirror::{Mirror, Origin},
};

pub(crate) struct DbCmdDelivery {
    pub(crate) mirror: Mirror,
    pub(crate) debname: String,
    pub(crate) size: u64,
    pub(crate) elapsed: Duration,
    pub(crate) partial: bool,
    pub(crate) client_ip: IpAddr,
}

pub(crate) struct DbCmdDownload {
    pub(crate) mirror: Mirror,
    pub(crate) debname: String,
    pub(crate) size: u64,
    pub(crate) elapsed: Duration,
    pub(crate) client_ip: IpAddr,
}

pub(crate) struct DbCmdOrigin {
    pub(crate) origin: Origin,
}

pub(crate) enum DatabaseCommand {
    Delivery(DbCmdDelivery),
    Download(DbCmdDownload),
    Origin(DbCmdOrigin),
}

pub(crate) async fn db_loop(
    database: Database,
    mut db_thread_rx: tokio::sync::mpsc::Receiver<DatabaseCommand>,
) {
    debug!("Database task started");

    let max_capacity = db_thread_rx.max_capacity();

    while let Some(cmd) = db_thread_rx.recv().await {
        match cmd {
            DatabaseCommand::Delivery(cmd) => {
                if let Err(err) = database
                    .register_delivery(
                        &cmd.mirror,
                        &cmd.debname,
                        cmd.size,
                        cmd.elapsed.into(),
                        cmd.partial,
                        cmd.client_ip,
                    )
                    .await
                {
                    error!("Failed to register delivery:  {err}");
                }
            }
            DatabaseCommand::Download(cmd) => {
                if let Err(err) = database
                    .register_download(
                        &cmd.mirror,
                        &cmd.debname,
                        cmd.size,
                        cmd.elapsed.into(),
                        cmd.client_ip,
                    )
                    .await
                {
                    error!("Failed to register download:  {err}");
                }
            }
            DatabaseCommand::Origin(cmd) => {
                if let Err(err) = database.add_origin(&cmd.origin.as_ref()).await {
                    error!("Failed to register origin:  {err}");
                }
            }
        }

        {
            static LOGGED_FULL: AtomicBool = AtomicBool::new(false);

            let curr_capacity = db_thread_rx.capacity();

            if LOGGED_FULL.load(Ordering::Relaxed) {
                if curr_capacity == max_capacity {
                    info!("Database command channel empty (0/{max_capacity})");
                    LOGGED_FULL.store(false, Ordering::Relaxed);
                }
            } else if curr_capacity == 0 {
                info!("Database command channel full ({max_capacity}/{max_capacity})");
                LOGGED_FULL.store(true, Ordering::Relaxed);
            }
        }
    }

    debug!("Database task stopped");
}
