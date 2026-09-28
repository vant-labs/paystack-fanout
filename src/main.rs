use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use clap::{Parser, ValueEnum};
use paystack_fanout::{
    app::{AppState, build_router, retention_loop},
    auth::hash_password,
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
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(
        long,
        global = true,
        env = "FANOUT_CONFIG",
        default_value = "config.toml"
    )]
    config: String,
    #[arg(long, global = true, env = "DATABASE_URL")]
    database_url: String,
    #[arg(long, global = true, env = "PORT", default_value_t = 8080)]
    port: u16,
    #[arg(long, global = true, value_enum, default_value_t = Role::All)]
    role: Role,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    CreateOwner {
        #[arg(long)]
        email: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let db = Database::connect(&args.database_url).await?;
    db.migrate().await?;
    if let Some(Command::CreateOwner { email }) = args.command {
        anyhow::ensure!(db.user_count().await? == 0, "an owner already exists");
        let password = rpassword::prompt_password("Owner password: ")?;
        let confirmation = rpassword::prompt_password("Confirm password: ")?;
        anyhow::ensure!(password == confirmation, "passwords do not match");
        let id = db.create_owner(&email, &hash_password(&password)?).await?;
        println!("Owner created: {id}");
        return Ok(());
    }
    let config = Config::load(&args.config)?;
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
