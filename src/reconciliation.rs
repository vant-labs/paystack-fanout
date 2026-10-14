use std::{sync::Arc, time::Duration};

use tokio::time::sleep;

use crate::{
    app::{AppState, resolve_provider_runtime},
    db::ReconciliationPurchase,
    provider::{PurchaseVerificationRequest, provider_for},
};

const INTERVAL: Duration = Duration::from_secs(15 * 60);

pub async fn run_reconciliation(state: Arc<AppState>) {
    loop {
        if let Err(error) = reconcile_once(&state).await {
            tracing::warn!(error = %error, "store reconciliation failed");
        }
        sleep(INTERVAL).await;
    }
}

pub async fn reconcile_once(state: &AppState) -> anyhow::Result<()> {
    state.refresh_runtime_if_stale().await;
    let config = state.runtime_config.read().await.clone();
    let secrets = state.runtime_secrets.read().await.clone();
    for provider_name in ["apple_server_notifications", "google_play_rtdn"] {
        let Some((source_name, source)) = config
            .source
            .iter()
            .find(|(_, source)| source.provider == provider_name)
        else {
            continue;
        };
        let Some(provider) = provider_for(provider_name) else {
            continue;
        };
        let secret = secrets
            .get(source_name)
            .cloned()
            .or_else(|| config.secret_for(source_name).ok())
            .unwrap_or_default();
        let runtime = resolve_provider_runtime(source, &secret);
        let purchases = state
            .db
            .list_reconciliation_purchases(if provider_name.starts_with("apple") {
                "apple"
            } else {
                "google"
            })
            .await?;
        for purchase in purchases {
            if let Err(error) =
                reconcile_purchase(state, provider, &runtime, source, purchase).await
            {
                tracing::warn!(provider = provider_name, error = %error, "store purchase reconciliation failed");
            }
        }
    }
    Ok(())
}

async fn reconcile_purchase(
    state: &AppState,
    provider: &'static dyn crate::provider::Provider,
    runtime: &crate::app::ResolvedProviderRuntime,
    source: &crate::config::SourceConfig,
    purchase: ReconciliationPurchase,
) -> anyhow::Result<()> {
    let request = PurchaseVerificationRequest {
        receipt: purchase.purchase_key,
        product_id: Some(purchase.product_id),
    };
    let mut event = provider
        .verify_purchase(&request, runtime.borrowed(source), &state.http)
        .await?;
    event.account_id = Some(purchase.account_id);
    state.db.apply_normalized_event(&event).await?;
    Ok(())
}
