use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use clap::{Parser, ValueEnum};
use paystack_fanout::{
    app::{AppState, build_router, retention_loop},
    config::Config,
    db::Database,
    worker::run_worker,
};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, ValueEnum)]
enum Role {
    All,
    Ingest,
    Worker,
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, env = "FANOUT_CONFIG", default_value = "config.toml")]
    config: String,
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    #[arg(long, env = "PORT", default_value_t = 8080)]
    port: u16,
    #[arg(long, value_enum, default_value_t = Role::All)]
    role: Role,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let config = Config::load(&args.config)?;
    let db = Database::connect(&args.database_url).await?;
    db.migrate().await?;
    let state = Arc::new(AppState::new(config, db)?);
    if matches!(args.role, Role::Worker | Role::All) {
        tokio::spawn(run_worker(state.clone()));
        tokio::spawn(retention_loop(state.clone()));
    }
    if matches!(args.role, Role::Ingest | Role::All) {
        let address = SocketAddr::from(([0, 0, 0, 0], args.port));
        tracing::info!(%address, "paystack fanout listening");
        axum::serve(
            tokio::net::TcpListener::bind(address).await?,
            build_router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    } else {
        tokio::signal::ctrl_c().await?;
    }
    Ok(())
}
