mod config;
mod controllers;

use crate::controllers::errors::HandlerError;
use axum::extract::Path;
use axum::{routing, Router};
use config::ConfigError;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::{select, signal};
use tower_http::services::ServeDir;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{error, info, Level};

#[derive(Error, Debug)]
enum AppSuccess {
  #[error("all operations completed")]
  Completed,
}

#[derive(Error, Debug)]
enum AppError {
  #[error("could not load config: {0}")]
  LoadConfig(#[from] ConfigError),
  #[error("could not bind to network interface: {0}")]
  BindTcpListener(std::io::Error),
  #[error("could not get TCP listener address: {0}")]
  GetListenerAddress(std::io::Error),
  #[error("could not start Axum server: {0}")]
  ServeApp(std::io::Error),
}

#[tokio::main]
async fn start() -> Result<AppSuccess, AppError> {
  let config = config::load()?;

  let listener = TcpListener::bind(SocketAddr::from((config.app.host, config.app.port)))
    .await
    .map_err(AppError::BindTcpListener)?;

  let api = Router::new().route(
    "/hello/:param",
    routing::get(|Path(param): Path<u32>| async move {
      if param == 0 {
        Ok(())
      } else {
        Err(HandlerError::Empty)
      }
    }),
  );
  let app = Router::new()
    .nest_service("/", ServeDir::new("frontend"))
    .nest("/api", api)
    .layer(
      TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_response(DefaultOnResponse::new().level(Level::INFO)),
    );

  info!(
    "backend listening on {}",
    listener
      .local_addr()
      .map_err(AppError::GetListenerAddress)?
  );

  axum::serve(listener, app)
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(AppError::ServeApp)?;

  Ok(AppSuccess::Completed)
}

fn main() {
  tracing_subscriber::fmt()
    .with_target(false)
    .compact()
    .with_max_level(Level::DEBUG)
    .init();

  info!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

  match start() {
    Ok(success) => info!("app exited successfully: {}", success),
    Err(err) => error!("app exited due to error: {}", err),
  }
}

async fn shutdown_signal() {
  let ctrl_c = async {
    signal::ctrl_c()
      .await
      .expect("failed to install Ctrl+C handler");
  };

  #[cfg(unix)]
  let terminate = async {
    signal::unix::signal(signal::unix::SignalKind::terminate())
      .expect("failed to install SIGTERM handler")
      .recv()
      .await;
  };
  #[cfg(not(unix))]
  let terminate = std::future::pending::<()>();

  select! {
    _ = ctrl_c => {},
    _ = terminate => {},
  }
}
