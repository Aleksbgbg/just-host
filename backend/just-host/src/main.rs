use thiserror::Error;
use tracing::{error, info, Level};

#[derive(Error, Debug)]
enum AppSuccess {
  #[error("all operations completed")]
  Completed,
}

#[derive(Error, Debug)]
enum AppError {}

fn start() -> Result<AppSuccess, AppError> {
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
