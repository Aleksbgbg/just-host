use serde::{Deserialize, Serialize};
use thiserror::Error;
use toml_env::Args;

#[derive(Serialize, Deserialize)]
pub struct Config {}

#[derive(Error, Debug)]
pub enum ConfigError {
  #[error(transparent)]
  Load(#[from] toml_env::Error),
  #[error("config file '.env.toml' was not found or was in an invalid format")]
  Invalid,
}

pub fn load() -> Result<Config, ConfigError> {
  toml_env::initialize(Args {
    config_variable_name: "config",
    ..Default::default()
  })?
  .ok_or(ConfigError::Invalid)
}
