use figment::providers::{Env, Format, Toml};
use figment::Figment;
use serde::Deserialize;
use thiserror::Error;

#[derive(Deserialize)]
pub struct Config {
  pub app: App,
}

#[derive(Deserialize)]
pub struct App {
  pub host: [u8; 4],
  pub port: u16,
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
