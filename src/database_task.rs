use core::net::IpAddr;
use std::{sync::OnceLock, time::Duration as StdDuration};

use coarsetime::Clock;
use hashbrown::HashMap;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, warn};

use crate::{
    database::{Database, DeliveryRow, DownloadRow, OriginRow},
    deb_mirror::{Mirror, Origin},
    error::ErrorReport,
    metrics,
};

/// Which per-transfer table a [`DbCmdTransfer`] is recorded in.
#[derive(Clone, Copy, Debug)]
pub(crate) enum TransferKind {
    /// A body shipped to a client (`deliveries`); `partial` marks a 206.
    Delivery { partial: bool },
    /// A body fetched from upstream and committed to the cache (`downloads`).
    Download,
}

impl TransferKind {
    /// Log noun for the record.
    fn noun(self) -> &'static str {
        match self {
            Self::Delivery { partial: _ } => "delivery",
            Self::Download => "download",
        }
    }
}

/// One completed transfer, delivery or download; the two tables share every
/// column but `partial`.
pub(crate) struct DbCmdTransfer {
    pub(crate) mirror: Mirror,
    pub(crate) debname: String,
    pub(crate) size: u64,
    pub(crate) elapsed: StdDuration,
    pub(crate) client_ip: IpAddr,
    pub(crate) kind: TransferKind,
}

pub(crate) struct DbCmdOrigin {
    pub(crate) origin: Origin,
}

pub(crate) struct DbCmdPing {
    pub(crate) reply: tokio::sync::oneshot::Sender<Result<(), sqlx::Error>>,
}

pub(crate) enum DatabaseCommand {
    Transfer(DbCmdTransfer),
    Origin(DbCmdOrigin),
    Ping(DbCmdPing),
}

pub(crate) static DB_TASK_QUEUE_SENDER: OnceLock<tokio::sync::mpsc::Sender<DatabaseCommand>> =
    OnceLock::new();

/// Send a `DatabaseCommand` on the channel, updating queue-depth metrics.
///
/// All call sites that enqueue work for the DB task should go through this
/// helper so `DB_QUEUE_DEPTH_PEAK` and `DB_COMMANDS_SENT` stay accurate.
///
/// During graceful shutdown the DB task closes its receiver and exits while
/// request tasks may still be finishing. Such sends are dropped (with a
/// metric bump) rather than panicking — losing a tail of telemetry events is
/// preferable to crashing the proxy.
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
    if tx.send(cmd).await.is_err() {
        metrics::DB_COMMANDS_DROPPED_SHUTDOWN.increment();
        return;
    }
    // Depth peaks are reached the instant a send completes — the consumer
    // can only decrease depth, never increase it — so one post-send sample
    // here captures every spike without needing a consumer-side sample.
    metrics::DB_QUEUE_DEPTH_PEAK.update(max_capacity.saturating_sub(tx.capacity()) as u64);
}

/// Synchronous variant of [`send_db_command`] for `Drop` impls and
/// pre-response paths that must not stall on a saturated queue:
/// `try_send` inline (the channel is rarely full) and fall back to a
/// spawned task only on saturation — preserving the no-drop semantics
/// without paying a task spawn per event or blocking the caller.
pub(crate) fn send_db_command_nonblocking(cmd: DatabaseCommand) {
    use tokio::sync::mpsc::error::TrySendError;

    let tx = DB_TASK_QUEUE_SENDER
        .get()
        .expect("Sender initialized in main_loop()");
    let max_capacity = tx.max_capacity();
    metrics::DB_COMMANDS_SENT.increment();
    match tx.try_send(cmd) {
        Ok(()) => {
            // See send_db_command for the peak-sampling rationale.
            metrics::DB_QUEUE_DEPTH_PEAK.update(max_capacity.saturating_sub(tx.capacity()) as u64);
        }
        Err(TrySendError::Full(cmd)) => {
            metrics::DB_QUEUE_FULL_WAITS.increment();
            let tx = tx.clone();
            tokio::task::spawn(async move {
                if tx.send(cmd).await.is_err() {
                    metrics::DB_COMMANDS_DROPPED_SHUTDOWN.increment();
                }
            });
        }
        Err(TrySendError::Closed(_cmd)) => {
            metrics::DB_COMMANDS_DROPPED_SHUTDOWN.increment();
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum FlushReason {
    BySize,
    ByTime,
    OnShutdown,
}

struct CachedMirror {
    id: i64,
    last_seen_observed: i64,
    last_seen_flushed: i64,
}

#[derive(Default)]
struct BatchBuffers {
    deliveries: Vec<DeliveryRow>,
    downloads: Vec<DownloadRow>,
    origins: Vec<OriginRow>,
}

impl BatchBuffers {
    fn len(&self) -> usize {
        self.deliveries.len() + self.downloads.len() + self.origins.len()
    }

    fn is_empty(&self) -> bool {
        self.deliveries.is_empty() && self.downloads.is_empty() && self.origins.is_empty()
    }
}

fn now_unix() -> i64 {
    i64::try_from(Clock::now_since_epoch().as_secs()).unwrap_or(i64::MAX)
}

fn ip_to_octets(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn convert_size_duration(size: u64, elapsed: StdDuration) -> Option<(i64, i64)> {
    let size = i64::try_from(size).ok()?;
    let duration = i64::try_from(elapsed.as_millis()).ok()?;
    Some((size, duration))
}

/// Resolve a mirror to its `mirrors_v2.id`, hitting the database only on a
/// cache miss. Always bumps the cached `last_seen_observed` to `now`.
///
/// Hot path: the lookup borrows `mirror` directly so per-event cache hits
/// allocate nothing. Only on a miss do we clone into the map.
async fn resolve_mirror_id(
    db: &Database,
    cache: &mut HashMap<Mirror, CachedMirror>,
    mirror: &Mirror,
    now: i64,
) -> Result<i64, sqlx::Error> {
    if let Some(entry) = cache.get_mut(mirror) {
        metrics::DB_MIRROR_CACHE_HITS.increment();
        if now > entry.last_seen_observed {
            entry.last_seen_observed = now;
        }
        return Ok(entry.id);
    }
    metrics::DB_MIRROR_CACHE_MISSES.increment();
    let (id, was_inserted) = db.upsert_mirror_id(mirror).await?;
    // The DB upsert just set last_seen to now; mirror that locally so the
    // periodic flush doesn't redundantly write it.
    cache.insert(
        mirror.clone(),
        CachedMirror {
            id,
            last_seen_observed: now,
            last_seen_flushed: now,
        },
    );
    metrics::DB_MIRROR_CACHE_ENTRIES.set(cache.len() as u64);
    if was_inserted {
        info!("Encountered new mirror: {mirror}");
    }
    Ok(id)
}

/// Stage a command into the batch buffers, resolving the mirror id first.
/// Errors during mirror resolution are logged and the command is dropped.
/// The Ping arm is a pass-through: no mirror resolution, replies inline.
async fn stage(
    db: &Database,
    cache: &mut HashMap<Mirror, CachedMirror>,
    buf: &mut BatchBuffers,
    cmd: DatabaseCommand,
    now: i64,
) {
    match cmd {
        DatabaseCommand::Transfer(c) => {
            let noun = c.kind.noun();
            let Some((size, duration)) = convert_size_duration(c.size, c.elapsed) else {
                metrics::DB_OPERATION_FAILED.increment();
                error!(
                    "Transfer size/duration conversion overflowed for {} from mirror {}; dropping the {noun} record",
                    c.debname, c.mirror
                );
                return;
            };
            let mirror_id = match resolve_mirror_id(db, cache, &c.mirror, now).await {
                Ok(id) => id,
                Err(err) => {
                    metrics::DB_OPERATION_FAILED.increment();
                    error!(
                        "Failed to resolve the mirror id for a {noun} of {debname} from mirror {mirror}; dropping the {noun} record:  {}",
                        ErrorReport(&err),
                        debname = c.debname,
                        mirror = c.mirror
                    );
                    return;
                }
            };
            let client_ip = ip_to_octets(c.client_ip);
            match c.kind {
                TransferKind::Delivery { partial } => buf.deliveries.push(DeliveryRow {
                    mirror_id,
                    debname: c.debname,
                    size,
                    duration,
                    partial: u8::from(partial),
                    client_ip,
                }),
                TransferKind::Download => buf.downloads.push(DownloadRow {
                    mirror_id,
                    debname: c.debname,
                    size,
                    duration,
                    client_ip,
                }),
            }
        }
        DatabaseCommand::Origin(c) => {
            let mirror_id = match resolve_mirror_id(db, cache, &c.origin.mirror, now).await {
                Ok(id) => id,
                Err(err) => {
                    metrics::DB_OPERATION_FAILED.increment();
                    error!(
                        "Failed to resolve the mirror id for an origin of mirror {mirror}; dropping the origin record:  {}",
                        ErrorReport(&err),
                        mirror = c.origin.mirror
                    );
                    return;
                }
            };
            let row = OriginRow {
                mirror_id,
                distribution: c.origin.distribution,
                component: c.origin.component,
                architecture: c.origin.architecture,
            };
            // Dedup within the batch: every Packages request for an origin
            // enqueues the same upsert, so a fleet refreshing one suite
            // produces runs of identical rows. Batches are <= flush size
            // (256), and origin rows are a small fraction, so a linear scan
            // is fine.
            if !buf.origins.contains(&row) {
                buf.origins.push(row);
            }
        }
        DatabaseCommand::Ping(c) => {
            let result = db.ping().await;
            if let Err(err) = &result {
                metrics::DB_OPERATION_FAILED.increment();
                error!(
                    "Failed to ping the database; reporting the health check as failing:  {}",
                    ErrorReport(err)
                );
            }
            // Replied-to-nobody is fine: the healthcheck timed out and
            // stopped waiting.
            if c.reply.send(result).is_err() {
                debug!("Healthcheck ping requester vanished before reply");
            }
        }
    }
}

/// Flush all three batch buffers in sequence. Errors are logged and the
/// affected buffer is dropped — the next flush starts with empty buffers.
async fn flush_batches(db: &Database, buf: &mut BatchBuffers, reason: FlushReason) {
    let total = buf.len();
    if total == 0 {
        return;
    }

    if let Err(err) = db.batch_insert_deliveries(&buf.deliveries).await {
        metrics::DB_OPERATION_FAILED.increment();
        error!(
            "Failed to flush {} delivery rows, dropping them:  {}",
            buf.deliveries.len(),
            ErrorReport(&err)
        );
    }
    buf.deliveries.clear();

    if let Err(err) = db.batch_insert_downloads(&buf.downloads).await {
        metrics::DB_OPERATION_FAILED.increment();
        error!(
            "Failed to flush {} download rows, dropping them:  {}",
            buf.downloads.len(),
            ErrorReport(&err)
        );
    }
    buf.downloads.clear();

    if let Err(err) = db.batch_upsert_origins(&buf.origins).await {
        metrics::DB_OPERATION_FAILED.increment();
        error!(
            "Failed to flush {} origin rows, dropping them:  {}",
            buf.origins.len(),
            ErrorReport(&err)
        );
    }
    buf.origins.clear();

    match reason {
        FlushReason::BySize => metrics::DB_BATCH_FLUSHES_BY_SIZE.increment(),
        FlushReason::ByTime => metrics::DB_BATCH_FLUSHES_BY_TIME.increment(),
        FlushReason::OnShutdown => metrics::DB_BATCH_FLUSHES_ON_SHUTDOWN.increment(),
    }
    metrics::DB_BATCH_SIZE_PEAK.update(total as u64);
}

/// Flush the in-memory `last_seen` deltas back to `mirrors_v2`. Only entries
/// whose observed timestamp is strictly newer than the last-flushed timestamp
/// are written.
async fn flush_last_seen(db: &Database, cache: &mut HashMap<Mirror, CachedMirror>) {
    let pairs: Vec<(i64, i64)> = cache
        .values()
        .filter(|e| e.last_seen_observed > e.last_seen_flushed)
        .map(|e| (e.id, e.last_seen_observed))
        .collect();

    if pairs.is_empty() {
        return;
    }

    match db.batch_update_mirror_last_seen(&pairs).await {
        Ok(rows) => {
            metrics::DB_MIRROR_LAST_SEEN_FLUSHED.increment_by(rows);
            for entry in cache.values_mut() {
                if entry.last_seen_observed > entry.last_seen_flushed {
                    entry.last_seen_flushed = entry.last_seen_observed;
                }
            }
        }
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to flush {} mirror last_seen rows, retrying at the next flush:  {}",
                pairs.len(),
                ErrorReport(&err)
            );
        }
    }
}

pub(crate) async fn db_loop(
    database: Database,
    mut db_thread_rx: tokio::sync::mpsc::Receiver<DatabaseCommand>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    flush_max_count: usize,
    flush_interval: StdDuration,
) {
    debug!("Database task started");

    let mut cache: HashMap<Mirror, CachedMirror> = HashMap::new();
    match database.load_all_mirror_ids().await {
        Ok(rows) => {
            cache.reserve(rows.len());
            for (id, mirror) in rows {
                cache.insert(
                    mirror,
                    CachedMirror {
                        id,
                        last_seen_observed: 0,
                        last_seen_flushed: 0,
                    },
                );
            }
            debug!("Mirror-id cache hydrated with {} entries", cache.len());
        }
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            warn!(
                "Failed to hydrate the mirror-id cache; starting empty and re-resolving every mirror on first use:  {}",
                ErrorReport(&err)
            );
        }
    }
    metrics::DB_MIRROR_CACHE_ENTRIES.set(cache.len() as u64);

    let mut buf = BatchBuffers::default();
    let mut interval = tokio::time::interval(flush_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // First tick fires immediately; consume it so the first real flush waits
    // a full interval after startup.
    interval.tick().await;

    let mut at_cap = false;
    let max_capacity = db_thread_rx.max_capacity();

    loop {
        tokio::select! {
            // Order matters under `biased`: shutdown must win, the periodic
            // tick must get polled (otherwise a saturated `recv()` would
            // starve it and `last_seen` flushes would never run), and only
            // then do we accept the next command.
            biased;
            res = shutdown.changed() => {
                if res.is_err() || *shutdown.borrow() {
                    debug!("Database task shutdown requested, draining...");
                    // Stop accepting new commands so any in-flight `send_db_command`
                    // observes a closed channel and can drop the event with a
                    // metric bump rather than queueing into a buffer we will
                    // never drain.
                    db_thread_rx.close();
                    while let Ok(cmd) = db_thread_rx.try_recv() {
                        let now = now_unix();
                        stage(&database, &mut cache, &mut buf, cmd, now).await;
                    }
                    flush_batches(&database, &mut buf, FlushReason::OnShutdown).await;
                    flush_last_seen(&database, &mut cache).await;
                    break;
                }
            }
            _ = interval.tick() => {
                if !buf.is_empty() {
                    flush_batches(&database, &mut buf, FlushReason::ByTime).await;
                }
                flush_last_seen(&database, &mut cache).await;
                // Sync point for `wait_for_next_db_flush`; keep the wording stable.
                debug!("Periodic database batch flush cycle complete");
            }
            maybe = db_thread_rx.recv() => {
                let Some(cmd) = maybe else {
                    debug!("Database task channel closed, draining...");
                    flush_batches(&database, &mut buf, FlushReason::OnShutdown).await;
                    flush_last_seen(&database, &mut cache).await;
                    break;
                };

                let now = now_unix();
                stage(&database, &mut cache, &mut buf, cmd, now).await;

                if buf.len() >= flush_max_count {
                    flush_batches(&database, &mut buf, FlushReason::BySize).await;
                }

                let curr_capacity = db_thread_rx.capacity();
                if curr_capacity == 0 {
                    if !at_cap {
                        let depth = max_capacity - curr_capacity;
                        // `send_db_command` awaits on a full queue, so request
                        // paths now block on database writes.
                        warn!(
                            "Database command channel full ({depth}/{max_capacity}); request paths now block on database writes; consider raising `db_channel_capacity`"
                        );
                        metrics::DB_QUEUE_FULL_TRANSITIONS.increment();
                        at_cap = true;
                    }
                } else if at_cap && curr_capacity == max_capacity {
                    info!("Database command channel empty (0/{max_capacity})");
                    at_cap = false;
                }
            }
        }
    }

    debug!("Database task stopped");
}
