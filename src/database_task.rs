use core::net::IpAddr;
use std::sync::OnceLock;

use coarsetime::Duration;
use log::{debug, error, info};

use crate::{
    database::Database,
    deb_mirror::{Mirror, Origin},
    metrics,
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

pub(crate) static DB_TASK_QUEUE_SENDER: OnceLock<tokio::sync::mpsc::Sender<DatabaseCommand>> =
    OnceLock::new();

/// Send a `DatabaseCommand` on the channel, updating queue-depth metrics.
///
/// All call sites that enqueue work for the DB task should go through this
/// helper so `DB_QUEUE_DEPTH_PEAK` and `DB_COMMANDS_SENT` stay accurate.
pub(crate) async fn send_db_command(cmd: DatabaseCommand) {
    let tx = DB_TASK_QUEUE_SENDER
        .get()
        .expect("Sender initialized in main_loop()");
    let max_capacity = tx.max_capacity();
    metrics::DB_COMMANDS_SENT.increment();
    // `capacity() == 0` means every slot is in flight, so this send must wait
    // for the DB task to drain one. Track it so operators can see how often
    // the channel is saturated and whether its configured size needs tuning.
    if tx.capacity() == 0 {
        metrics::DB_QUEUE_FULL_WAITS.increment();
    }
    tx.send(cmd).await.expect("database task should not die");
    // Depth peaks are reached the instant a send completes — the consumer
    // can only decrease depth, never increase it — so one post-send sample
    // here captures every spike without needing a consumer-side sample.
    metrics::DB_QUEUE_DEPTH_PEAK.update(max_capacity.saturating_sub(tx.capacity()) as u64);
}

pub(crate) async fn db_loop(
    database: Database,
    mut db_thread_rx: tokio::sync::mpsc::Receiver<DatabaseCommand>,
) {
    debug!("Database task started");

    let mut at_cap = false;
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
                    metrics::DB_OPERATION_FAILED.increment();
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
                    metrics::DB_OPERATION_FAILED.increment();
                    error!("Failed to register download:  {err}");
                }
            }
            DatabaseCommand::Origin(cmd) => {
                if let Err(err) = database.add_origin(&cmd.origin.as_ref()).await {
                    metrics::DB_OPERATION_FAILED.increment();
                    error!("Failed to register origin:  {err}");
                }
            }
        }

        let curr_capacity = db_thread_rx.capacity();
        if curr_capacity == 0 {
            if !at_cap {
                info!("Database command channel full ({max_capacity}/{max_capacity})");
                metrics::DB_QUEUE_FULL_TRANSITIONS.increment();
                at_cap = true;
            }
        } else if at_cap && curr_capacity == max_capacity {
            info!("Database command channel empty (0/{max_capacity})");
            at_cap = false;
        }
    }

    debug!("Database task stopped");
}
