use core::{net::IpAddr, time::Duration};

use log::{debug, error};

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

    while let Some(cmd) = db_thread_rx.recv().await {
        match cmd {
            DatabaseCommand::Delivery(cmd) => {
                if let Err(err) = database
                    .register_deliviery(
                        &cmd.mirror,
                        &cmd.debname,
                        cmd.size,
                        cmd.elapsed,
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
                        cmd.elapsed,
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
    }

    debug!("Database task stopped");
}
