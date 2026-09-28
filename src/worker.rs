use std::{sync::Arc, time::Instant};

use chrono::Utc;
use futures_util::StreamExt;
use tokio::time::{Duration, sleep};

use crate::{app::AppState, db::ClaimedDelivery};

pub const MAX_ATTEMPTS: i32 = 10;

pub fn retry_delay(attempt: i32) -> Option<Duration> {
    match attempt {
        1 => Some(Duration::from_secs(30)),
        2 => Some(Duration::from_mins(2)),
        3 => Some(Duration::from_mins(10)),
        4 => Some(Duration::from_mins(30)),
        5 => Some(Duration::from_hours(1)),
        6 => Some(Duration::from_hours(3)),
        7 => Some(Duration::from_hours(6)),
        8 => Some(Duration::from_hours(12)),
        9 => Some(Duration::from_hours(24)),
        _ => None,
    }
}

pub async fn run_worker(state: Arc<AppState>) {
    loop {
        match state.db.claim_delivery().await {
            Ok(Some(delivery)) => process_one(&state, delivery).await,
            Ok(None) => sleep(Duration::from_millis(500)).await,
            Err(error) => {
                tracing::error!(error = %error, "claiming delivery failed");
                sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

pub async fn process_one(state: &AppState, delivery: ClaimedDelivery) {
    let started = Utc::now();
    let timer = Instant::now();
    let request = state
        .http
        .post(&delivery.destination_url)
        .header("content-type", &delivery.content_type)
        .header("x-paystack-signature", &delivery.signature)
        .header("x-fanout-event-id", delivery.event_id.to_string())
        .header("x-fanout-attempt", delivery.attempt.to_string())
        .body(delivery.raw_body.clone())
        .send()
        .await;
    let latency_ms = i32::try_from(timer.elapsed().as_millis()).unwrap_or(i32::MAX);
    let finished = Utc::now();
    state
        .metrics
        .observe_delivery_ms(u64::try_from(latency_ms).unwrap_or_default());
    match request {
        Ok(response) if response.status().is_success() => {
            let status = response.status().as_u16();
            let body = read_response_body(response).await;
            if let Err(error) = state
                .db
                .record_success(
                    &delivery,
                    started,
                    finished,
                    status,
                    body.as_deref(),
                    latency_ms,
                )
                .await
            {
                tracing::error!(error = %error, event_id = %delivery.event_id, "recording delivery success failed");
            }
            state
                .metrics
                .delivered
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(response) => {
            let status = response.status().as_u16();
            let body = read_response_body(response).await;
            finish_failure(
                state,
                &delivery,
                started,
                finished,
                Some(status),
                body.as_deref(),
                None,
                latency_ms,
            )
            .await;
        }
        Err(error) => {
            finish_failure(
                state,
                &delivery,
                started,
                finished,
                None,
                None,
                Some(&error.to_string()),
                latency_ms,
            )
            .await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn finish_failure(
    state: &AppState,
    delivery: &ClaimedDelivery,
    started: chrono::DateTime<Utc>,
    finished: chrono::DateTime<Utc>,
    status: Option<u16>,
    body: Option<&str>,
    error: Option<&str>,
    latency_ms: i32,
) {
    let next = retry_delay(delivery.attempt).map(|delay| {
        Utc::now() + chrono::Duration::from_std(jitter(delay)).expect("jitter duration is valid")
    });
    let is_dead = next.is_none();
    if let Err(db_error) = state
        .db
        .record_failure(
            delivery, started, finished, status, body, error, latency_ms, next,
        )
        .await
    {
        tracing::error!(error = %db_error, event_id = %delivery.event_id, "recording delivery failure failed");
        return;
    }
    if is_dead {
        state
            .metrics
            .dead
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        state
            .alert(format!(
                "Paystack event {} delivery is dead after {} attempts",
                delivery.event_id, delivery.attempt
            ))
            .await;
    } else {
        state
            .metrics
            .retries
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

fn jitter(delay: Duration) -> Duration {
    let ratio = 0.8 + (f64::from(rand::random::<u16>()) / f64::from(u16::MAX)) * 0.4;
    Duration::from_secs_f64(delay.as_secs_f64() * ratio)
}

async fn read_response_body(response: reqwest::Response) -> Option<String> {
    let mut bytes = Vec::with_capacity(2_048);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else { break };
        let remaining = 2_048usize.saturating_sub(bytes.len());
        bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if bytes.len() >= 2_048 {
            break;
        }
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_schedule_and_max_attempts() {
        assert_eq!(retry_delay(1).unwrap().as_secs(), 30);
        assert_eq!(retry_delay(2).unwrap().as_secs(), 120);
        assert_eq!(retry_delay(3).unwrap().as_secs(), 600);
        assert_eq!(retry_delay(9).unwrap().as_secs(), 86_400);
        assert!(retry_delay(MAX_ATTEMPTS).is_none());
    }
}
