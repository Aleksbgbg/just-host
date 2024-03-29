mod config;
mod controllers;
mod models;
mod secure;
mod snowflake;

use crate::secure::Bytes;
use axum::{middleware, routing, Router};
use config::ConfigError;
use controllers::user;
use diesel::{Connection, ConnectionError, PgConnection};
use diesel_async::pooled_connection::deadpool::{BuildError, Pool};
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::AsyncPgConnection;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use fs::filesystem;
use snowflake::SnowflakeGenerator;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinError;
use tokio::{select, signal, task};
use tower_http::services::ServeDir;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{error, info, Level};

const SECRET_LEN: usize = 32;

const ROOT_PREFIX: &str = "/";
const API_PREFIX: &str = "/api";

#[derive(Error, Debug)]
enum AppSuccess {
  #[error("all operations completed")]
  Completed,
}

#[derive(Error, Debug)]
enum AppError {
  #[error("could not load config: {0}")]
  LoadConfig(#[from] ConfigError),
  #[error("could not join blocking task: {0}")]
  JoinBlockingTask(#[from] JoinError),
  #[error("could not connect to database at startup: {0}")]
  InitialConnection(#[from] ConnectionError),
  #[error("could not apply database migrations: {0}")]
  RunMigrations(String),
  #[error("could not build database connection pool: {0}")]
  BuildConnectionPool(#[from] BuildError),
  #[error("could not bind to network interface: {0}")]
  BindTcpListener(std::io::Error),
  #[error("could not open auth secret: {0}")]
  OpenAuthSecret(std::io::Error),
  #[error("could not read auth secret metadata: {0}")]
  ReadAuthSecretMetadata(std::io::Error),
  #[error("could not generate auth secret: {0}")]
  GenerateAuthSecret(#[from] rand_core::Error),
  #[error("could not write auth secret: {0}")]
  WriteAuthSecret(std::io::Error),
  #[error("could not read auth secret: {0}")]
  ReadAuthSecret(std::io::Error),
  #[error("could not get TCP listener address: {0}")]
  GetListenerAddress(std::io::Error),
  #[error("could not start Axum server: {0}")]
  ServeApp(std::io::Error),
}

filesystem!(
  MainFs,
  r"
<ConfigRoot>
  auth_secret #auth_secret
"
);

struct State {
  connection_pool: Pool<AsyncPgConnection>,
  user_snowflake: SnowflakeGenerator,
  auth_secret: Vec<u8>,
}

type AppState = Arc<State>;

#[tokio::main]
async fn start() -> Result<AppSuccess, AppError> {
  let config = config::load()?;
  let fs = MainFs::new().set(MainFsVar::ConfigRoot, config.app.config_root);
  let connection_string = config.database.connection_string();

  {
    let connection_string = connection_string.clone();
    task::spawn_blocking(move || {
      const MIGRATIONS: EmbeddedMigrations = embed_migrations!("../migrations");
      PgConnection::establish(&connection_string)?
        .run_pending_migrations(MIGRATIONS)
        .map_err(|err| AppError::RunMigrations(err.to_string()))?;

      Ok::<_, AppError>(())
    })
    .await??;
  }

  let listener = TcpListener::bind(SocketAddr::from((config.app.host, config.app.port)))
    .await
    .map_err(AppError::BindTcpListener)?;

  let connection_pool = Pool::builder(AsyncDieselConnectionManager::<AsyncPgConnection>::new(
    connection_string,
  ))
  .build()?;
  let auth_secret = async {
    let mut file = fs
      .auth_secret()
      .open()
      .await
      .map_err(AppError::OpenAuthSecret)?;
    if file
      .metadata()
      .await
      .map_err(AppError::ReadAuthSecretMetadata)?
      .len()
      == 0
    {
      let secret = secure::random_bytes(Bytes(SECRET_LEN))?;
      file
        .write_all(&secret)
        .await
        .map_err(AppError::WriteAuthSecret)?;
      Ok::<_, AppError>(secret)
    } else {
      let mut secret = Vec::with_capacity(SECRET_LEN);
      file
        .read_to_end(&mut secret)
        .await
        .map_err(AppError::ReadAuthSecret)?;
      Ok(secret)
    }
  }
  .await?;

  let state = Arc::new(State {
    connection_pool,
    user_snowflake: SnowflakeGenerator::new(0),
    auth_secret,
  });

  let api = Router::new()
    .route("/register", routing::post(user::register))
    .route("/login", routing::post(user::login))
    .route(
      "/user",
      routing::get(user::get).layer(middleware::from_fn_with_state(
        Arc::clone(&state),
        user::extract,
      )),
    )
    .with_state(state);
  let app = Router::new()
    .nest_service(ROOT_PREFIX, ServeDir::new("frontend"))
    .nest(API_PREFIX, api)
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
