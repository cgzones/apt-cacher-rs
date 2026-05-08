use std::{convert::Infallible, pin::Pin, sync::Arc, task::Poll::Ready};

use http_body::{Body, Frame, SizeHint};
use memmap2::Mmap;
use tracing::info;

use crate::{
    cache_layout::{CachedFlavor, ConnectionDetails},
    client_counter,
    database_task::{DatabaseCommand, DbCmdDelivery, send_db_command},
    humanfmt::HumanFmt,
    metrics,
    precise_instant::PreciseInstant,
    rate_log,
};

const MMAP_FRAME_SIZE: usize = 2 * 1024 * 1024; // 2MiB

pub(crate) struct MmapBody {
    mapping: Arc<Mmap>,
    position: usize,
    length: usize,
    partial: bool,
    start: PreciseInstant,
    conn_details: Option<ConnectionDetails>,
    _counter: client_counter::ClientDownload,
}

impl MmapBody {
    #[must_use]
    pub(crate) fn new(
        mapping: Mmap,
        length: usize,
        partial: bool,
        conn_details: ConnectionDetails,
    ) -> Self {
        metrics::REQUESTS_MMAP.increment();
        Self {
            mapping: Arc::new(mapping),
            position: 0,
            length,
            partial,
            start: PreciseInstant::now(),
            conn_details: Some(conn_details),
            _counter: client_counter::ClientDownload::new(),
        }
    }
}

impl Drop for MmapBody {
    fn drop(&mut self) {
        let size = self.length as u64;
        let partial = self.partial;
        let elapsed = self.start.elapsed();
        let transferred_bytes = self.position as u64;
        metrics::BYTES_SERVED_MMAP.increment_by(transferred_bytes);
        let cd = self.conn_details.take().expect("set in new()");
        tokio::task::spawn(async move {
            let aliased = match cd.aliased_host {
                Some(alias) => format!(" aliased to host {alias}"),
                None => String::new(),
            };
            let in_time = cd.request_received_at.elapsed();
            let volatile = if cd.cached_flavor == CachedFlavor::Volatile {
                "volatile "
            } else {
                ""
            };
            if transferred_bytes == size {
                metrics::SERVED_MMAP.increment();
                metrics::SERVED_TOTAL.increment();
                info!(
                    "Served cached {volatile}file {} from mirror {}{} for client {} in {} via mmap ({})",
                    cd.debname,
                    cd.mirror,
                    aliased,
                    cd.client,
                    HumanFmt::Time(in_time),
                    rate_log::client_segment(size, elapsed),
                );

                let cmd = DatabaseCommand::Delivery(DbCmdDelivery {
                    mirror: cd.mirror,
                    debname: cd.debname,
                    size,
                    elapsed,
                    partial,
                    client_ip: cd.client.ip(),
                });
                send_db_command(cmd).await;
            } else {
                let segment = rate_log::client_disconnect_segment(transferred_bytes, elapsed);
                info!(
                    "Aborted serving cached {volatile}file {} from mirror {}{} for client {} in {} via mmap ({segment})",
                    cd.debname,
                    cd.mirror,
                    aliased,
                    cd.client,
                    HumanFmt::Time(in_time),
                );
            }
        });
    }
}

pub(crate) struct MmapData {
    mapping: Arc<Mmap>,
    position: usize,
    remaining: usize,
}

impl bytes::buf::Buf for MmapData {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn chunk(&self) -> &[u8] {
        &self.mapping[self.position..(self.position + self.remaining)]
    }

    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.remaining, "suggested by trait");
        self.position += cnt;
        self.remaining -= cnt;
    }
}

impl Body for MmapBody {
    type Data = MmapData;
    type Error = Infallible;

    fn is_end_stream(&self) -> bool {
        debug_assert!(
            self.position <= self.length,
            "position must not exceed length"
        );
        self.position == self.length
    }

    fn size_hint(&self) -> SizeHint {
        debug_assert!(
            self.position <= self.length,
            "position must not exceed length"
        );
        SizeHint::with_exact((self.length - self.position) as u64)
    }

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // same logic as in Self::is_end_stream()
        debug_assert!(
            self.position <= self.length,
            "position must not exceed length"
        );
        let remaining_total = self.length - self.position;
        if remaining_total == 0 {
            return Ready(None);
        }

        let chunk_size = remaining_total.min(MMAP_FRAME_SIZE);

        let frame = Frame::data(MmapData {
            mapping: Arc::clone(&self.mapping),
            position: self.position,
            remaining: chunk_size,
        });

        self.as_mut().position += chunk_size;

        Ready(Some(Ok(frame)))
    }
}
