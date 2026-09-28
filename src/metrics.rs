use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    fmt::Write,
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Default)]
pub struct Metrics {
    pub received: AtomicU64,
    pub verified_failed: AtomicU64,
    pub duplicates: AtomicU64,
    pub delivered: AtomicU64,
    pub retries: AtomicU64,
    pub dead: AtomicU64,
    pub unrouted: AtomicU64,
    pub would_unrouted: AtomicU64,
    latency_buckets: [AtomicU64; 6],
    latency_sum_ms: AtomicU64,
    latency_count: AtomicU64,
    last_signature_log_ms: AtomicU64,
}

impl Metrics {
    pub fn should_log_signature_failure(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
            });
        let last = self.last_signature_log_ms.load(Ordering::Relaxed);
        if now.saturating_sub(last) < 60_000 {
            return false;
        }
        self.last_signature_log_ms
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    pub fn observe_delivery_ms(&self, milliseconds: u64) {
        self.latency_sum_ms
            .fetch_add(milliseconds, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        for (bucket, limit) in
            self.latency_buckets
                .iter()
                .zip([100, 500, 1_000, 5_000, 10_000, u64::MAX])
        {
            if milliseconds <= limit {
                bucket.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
    }

    pub fn render(&self) -> String {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let buckets = [100, 500, 1_000, 5_000, 10_000, u64::MAX];
        let mut out = String::new();
        for (bucket, limit) in self.latency_buckets.iter().zip(buckets) {
            let label = if limit == u64::MAX {
                "+Inf".to_owned()
            } else {
                limit.to_string()
            };
            let _ = writeln!(
                out,
                "fanout_delivery_latency_ms_bucket{{le=\"{label}\"}} {}\n",
                load(bucket)
            );
        }
        let _ = writeln!(
            out,
            "fanout_delivery_latency_ms_sum {}\n",
            load(&self.latency_sum_ms)
        );
        let _ = writeln!(
            out,
            "fanout_delivery_latency_ms_count {}\n",
            load(&self.latency_count)
        );
        for (name, value) in [
            ("received", load(&self.received)),
            ("verified_failed", load(&self.verified_failed)),
            ("duplicates", load(&self.duplicates)),
            ("delivered", load(&self.delivered)),
            ("retries", load(&self.retries)),
            ("dead", load(&self.dead)),
            ("unrouted", load(&self.unrouted)),
            ("would_unrouted", load(&self.would_unrouted)),
        ] {
            let _ = writeln!(out, "fanout_{name} {value}");
        }
        out
    }
}
