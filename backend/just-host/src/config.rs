use figment::Figment;
use figment::providers::{Env, Format, Toml};
use serde::Deserialize;
use thiserror::Error;

#[derive(Deserialize)]
pub struct Config {
  pub app: App,
  pub database: Database,
}

#[derive(Deserialize)]
pub struct App {
  pub host: [u8; 4],
  pub port: u16,
  pub config_root: String,
}

#[derive(Deserialize)]
pub struct Database {
  pub host: String,
  pub port: u16,
  pub username: String,
  pub password: String,
  pub database: String,
}

impl Database {
  pub fn connection_string(&self) -> String {
    format!(
      "postgres://{}:{}@{}:{}/{}",
      self.username, self.password, self.host, self.port, self.database
    )
  }
}

#[derive(Error, Debug)]
pub enum ConfigError {
  #[error(transparent)]
  Load(#[from] figment::Error),
}

pub fn load() -> Result<Config, ConfigError> {
  Ok(
    Figment::new()
      .merge(Toml::file(".env.toml"))
      .merge(Env::raw().split("_"))
      .extract()?,
  )
}
