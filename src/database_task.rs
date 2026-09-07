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

pub(crate) enum DatabaseCommand {
    Transfer(DbCmdTransfer),
    Origin(Origin),
    /// Round-trips the queue so the healthcheck learns the DB task is alive
    /// and draining; the reply carries the probe query's own result.
    Ping(tokio::sync::oneshot::Sender<Result<(), sqlx::Error>>),
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
    record_queue_depth(tx);
}

/// Sample the channel depth into `DB_QUEUE_DEPTH_PEAK`.
///
/// Depth peaks are reached the instant a send completes — the consumer can
/// only decrease depth, never increase it — so one post-send sample here
/// captures every spike without needing a consumer-side sample.
fn record_queue_depth(tx: &tokio::sync::mpsc::Sender<DatabaseCommand>) {
    metrics::DB_QUEUE_DEPTH_PEAK.update(tx.max_capacity().saturating_sub(tx.capacity()) as u64);
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
    metrics::DB_COMMANDS_SENT.increment();
    match tx.try_send(cmd) {
        Ok(()) => record_queue_depth(tx),
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
/// cache miss. Always bumps the cached `last_seen_observed` to now.
///
/// Hot path: the lookup borrows `mirror` directly so per-event cache hits
/// allocate nothing. Only on a miss do we clone into the map.
async fn resolve_mirror_id(
    db: &Database,
    cache: &mut HashMap<Mirror, CachedMirror>,
    mirror: &Mirror,
) -> Result<i64, sqlx::Error> {
    let now = now_unix();
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
            let mirror_id = match resolve_mirror_id(db, cache, &c.mirror).await {
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
        DatabaseCommand::Origin(origin) => {
            let mirror_id = match resolve_mirror_id(db, cache, &origin.mirror).await {
                Ok(id) => id,
                Err(err) => {
                    metrics::DB_OPERATION_FAILED.increment();
                    error!(
                        "Failed to resolve the mirror id for an origin of mirror {mirror}; dropping the origin record:  {}",
                        ErrorReport(&err),
                        mirror = origin.mirror
                    );
                    return;
                }
            };
            let row = OriginRow {
                mirror_id,
                distribution: origin.fields.distribution,
                component: origin.fields.component,
                architecture: origin.fields.architecture,
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
        DatabaseCommand::Ping(reply) => {
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
            if reply.send(result).is_err() {
                debug!("Healthcheck ping requester vanished before reply");
            }
        }
    }
}

// Commands are received in chunks of up to this many: one `select!` round
// (shutdown watch, interval tick, channel) and one permit release per chunk
// instead of per command. The `biased` order already keeps the tick and the
// shutdown arm ahead of the channel, so the chunk size only amortises that
// overhead; it is not what keeps a busy producer from starving them.
const RECEIVE_BATCH_LIMIT: usize = 32;

/// Empty the reusable receive buffer without exceeding the row flush
/// threshold. A command contributes at most one row.
async fn stage_received(
    db: &Database,
    cache: &mut HashMap<Mirror, CachedMirror>,
    buf: &mut BatchBuffers,
    received: &mut Vec<DatabaseCommand>,
    flush_max_count: usize,
) {
    for cmd in received.drain(..) {
        stage(db, cache, buf, cmd).await;
        if buf.len() >= flush_max_count {
            flush_batches(db, buf, FlushReason::BySize).await;
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
    let receive_limit = RECEIVE_BATCH_LIMIT.min(max_capacity);
    let mut received = Vec::with_capacity(receive_limit);

    loop {
        tokio::select! {
            // Order matters under `biased`: shutdown must win, the periodic
            // tick must get polled (otherwise a saturated `recv_many()` would
            // starve it and `last_seen` flushes would never run), and only
            // then do we accept the next bounded chunk of commands.
            biased;
            res = shutdown.changed() => {
                if res.is_err() || *shutdown.borrow() {
                    debug!("Database task shutdown requested, draining...");
                    // Stop accepting new commands so any in-flight `send_db_command`
                    // observes a closed channel and can drop the event with a
                    // metric bump rather than queueing into a buffer we will
                    // never drain.
                    db_thread_rx.close();
                    // Non-blocking drain: a `send` that was handed a slot
                    // before `close()` fails on its next poll anyway, so
                    // nothing is gained by parking on the channel, and a
                    // parked drain could only end via the caller's timeout.
                    // The whole backlog goes out in one shutdown flush;
                    // `batch_insert_*` chunk to the bind-parameter limit.
                    while let Ok(cmd) = db_thread_rx.try_recv() {
                        stage(&database, &mut cache, &mut buf, cmd).await;
                    }
                    flush_batches(&database, &mut buf, FlushReason::OnShutdown).await;
                    flush_last_seen(&database, &mut cache).await;
                    break;
                }
            }
            _ = interval.tick() => {
                flush_batches(&database, &mut buf, FlushReason::ByTime).await;
                flush_last_seen(&database, &mut cache).await;
                // Sync point for `wait_for_next_db_flush`; keep the wording stable.
                debug!("Periodic database batch flush cycle complete");
            }
            count = db_thread_rx.recv_many(&mut received, receive_limit) => {
                if count == 0 {
                    debug!("Database task channel closed, draining...");
                    flush_batches(&database, &mut buf, FlushReason::OnShutdown).await;
                    flush_last_seen(&database, &mut cache).await;
                    break;
                }

                // Was the channel full when this chunk was taken? Sample it
                // from the queue length rather than `capacity()`: the slots a
                // chunk frees go to parked senders first, so `capacity()`
                // only reads zero again once a whole chunk's worth of them
                // was waiting. Sampled once per chunk; the producer-side
                // full-wait/depth counters remain per send.
                let was_full = count.saturating_add(db_thread_rx.len()) >= max_capacity;
                stage_received(&database, &mut cache, &mut buf, &mut received, flush_max_count).await;

                if was_full && !at_cap {
                    // `send_db_command` awaits on a full queue, so request
                    // paths now block on database writes.
                    warn!(
                        "Database command channel full ({max_capacity}/{max_capacity}); request paths now block on database writes; consider raising `db_channel_capacity`"
                    );
                    metrics::DB_QUEUE_FULL_TRANSITIONS.increment();
                    at_cap = true;
                } else if at_cap && db_thread_rx.capacity() == max_capacity {
                    info!("Database command channel empty (0/{max_capacity})");
                    at_cap = false;
                }
            }
        }
    }

    debug!("Database task stopped");
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::sync::{mpsc, oneshot, watch};
    use tokio::task::JoinHandle;
    use tokio::time::{sleep, timeout};

    use super::*;
    use crate::{deb_mirror::OriginFields, test_support::structured_mirror};

    const TEST_TIMEOUT: StdDuration = StdDuration::from_secs(5);
    const HOST: &str = "deb.example.org";
    const PATH: &str = "debian";

    struct Fixture {
        _dir: tempfile::TempDir,
        database: Database,
    }

    impl Fixture {
        async fn new() -> Self {
            let (dir, database) = Database::temp().await;
            // Seed the one mirror so hydration serves every command from the
            // mirror-id cache; see `Database::insert_mirror_host`.
            database.insert_mirror_host(HOST, PATH).await;
            Self {
                _dir: dir,
                database,
            }
        }

        fn spawn(
            &self,
            rx: mpsc::Receiver<DatabaseCommand>,
            shutdown_rx: watch::Receiver<bool>,
            flush_max_count: usize,
            flush_interval: StdDuration,
        ) -> JoinHandle<()> {
            tokio::spawn(db_loop(
                self.database.clone(),
                rx,
                shutdown_rx,
                flush_max_count,
                flush_interval,
            ))
        }

        /// `(rows, bytes)` over deliveries and downloads of the seeded mirror.
        async fn transfers(&self) -> (i64, i64) {
            let stats = self
                .database
                .get_mirrors_with_stats()
                .await
                .expect("mirror stats");
            assert_eq!(stats.len(), 1, "only the seeded mirror exists");
            let stats = stats.first().expect("asserted above");
            (
                stats.delivery_count + stats.download_count,
                stats.total_delivery_size + stats.total_download_size,
            )
        }

        async fn origins(&self) -> usize {
            self.database.get_origins().await.expect("origins").len()
        }
    }

    fn mirror() -> Mirror {
        structured_mirror(HOST, PATH)
    }

    fn transfer(index: u64) -> DatabaseCommand {
        DatabaseCommand::Transfer(DbCmdTransfer {
            mirror: mirror(),
            debname: format!("test_{index}_amd64.deb"),
            size: index + 1,
            elapsed: StdDuration::from_millis(1),
            client_ip: Ipv4Addr::LOCALHOST.into(),
            kind: if index.is_multiple_of(2) {
                TransferKind::Delivery { partial: false }
            } else {
                TransferKind::Download
            },
        })
    }

    async fn ping(tx: &mpsc::Sender<DatabaseCommand>) {
        let (reply, received) = oneshot::channel();
        assert!(tx.send(DatabaseCommand::Ping(reply)).await.is_ok());
        timeout(TEST_TIMEOUT, received)
            .await
            .expect("ping timeout")
            .expect("reply")
            .expect("database ping");
    }

    #[tokio::test]
    async fn receive_chunks_preserve_size_flush_and_channel_close_tail() {
        let fixture = Fixture::new().await;
        let (tx, rx) = mpsc::channel(128);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = fixture.spawn(rx, shutdown_rx, 7, StdDuration::from_secs(3600));
        // More than two receive chunks, with a row threshold that does not
        // divide the receive limit. Ping must not force an early row flush.
        for index in 0..75 {
            assert!(tx.send(transfer(index)).await.is_ok());
        }
        ping(&tx).await;
        assert_eq!(fixture.transfers().await, (70, 2485));
        drop(tx);
        timeout(TEST_TIMEOUT, task)
            .await
            .expect("drain timeout")
            .expect("db task");
        assert_eq!(fixture.transfers().await, (75, 2850));
    }

    #[tokio::test]
    async fn shutdown_drains_a_backlog_larger_than_one_chunk() {
        let fixture = Fixture::new().await;
        let (tx, rx) = mpsc::channel(128);
        for index in 0..75 {
            assert!(tx.send(transfer(index)).await.is_ok());
        }
        let (tail_reply, tail_received) = oneshot::channel();
        assert!(tx.send(DatabaseCommand::Ping(tail_reply)).await.is_ok());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        shutdown_tx.send(true).expect("shutdown");
        let task = fixture.spawn(rx, shutdown_rx, 7, StdDuration::from_secs(3600));
        timeout(TEST_TIMEOUT, tx.closed())
            .await
            .expect("receiver closes");
        // The command queued behind the backlog is still answered.
        timeout(TEST_TIMEOUT, tail_received)
            .await
            .expect("queued tail timeout")
            .expect("queued tail reply")
            .expect("queued tail ping");
        timeout(TEST_TIMEOUT, task)
            .await
            .expect("drain timeout")
            .expect("db task");
        assert_eq!(fixture.transfers().await, (75, 2850));
    }

    #[tokio::test]
    async fn busy_queue_still_flushes_by_time_and_observes_shutdown() {
        let fixture = Fixture::new().await;
        let (tx, rx) = mpsc::channel(128);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = fixture.spawn(rx, shutdown_rx, 4096, StdDuration::from_millis(10));
        ping(&tx).await;
        // Repeating one origin keeps the staged row count below the size
        // threshold, even with a continuously replenished command channel.
        let producer = tokio::spawn(async move {
            let mirror = mirror();
            let fields = OriginFields {
                distribution: "stable".to_owned(),
                component: "main".to_owned(),
                architecture: "amd64".to_owned(),
            };
            loop {
                let origin = Origin {
                    mirror: mirror.clone(),
                    fields: fields.clone(),
                };
                if tx.send(DatabaseCommand::Origin(origin)).await.is_err() {
                    break;
                }
            }
        });
        timeout(TEST_TIMEOUT, async {
            while fixture.origins().await != 1 {
                sleep(StdDuration::from_millis(1)).await;
            }
        })
        .await
        .expect("periodic flush while producer is active");
        assert!(!producer.is_finished());
        shutdown_tx.send(true).expect("shutdown");
        timeout(TEST_TIMEOUT, task)
            .await
            .expect("shutdown timeout")
            .expect("db task");
        timeout(TEST_TIMEOUT, producer)
            .await
            .expect("producer timeout")
            .expect("producer");
    }
}
