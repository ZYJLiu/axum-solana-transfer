// RUST_LOG=info cargo watch -x 'run'
mod config;
mod handlers;
mod routes;
mod services;
mod tests;

use anyhow::Result;
use axum::Router;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Listening on {}", listener.local_addr()?);
    axum::serve(listener, app()).await?;
    Ok(())
}

pub fn app() -> Router {
    Router::new()
        .merge(routes::transfer::router())
        .layer(CorsLayer::permissive())
}
