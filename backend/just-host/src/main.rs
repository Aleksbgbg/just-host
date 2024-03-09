mod config;

use config::ConfigError;
use thiserror::Error;
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
}

#[tokio::main]
async fn start() -> Result<AppSuccess, AppError> {
  let _config = config::load()?;

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
