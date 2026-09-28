#![forbid(unsafe_code)]

pub mod app;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod dashboard;
pub mod db;
pub mod metrics;
pub mod openapi;
pub mod provider;
pub mod routing;
pub mod security;
pub mod worker;

pub use app::{AppState, build_router};
