use crate::snowflake::SnowflakeGenerator;
use diesel_derive_newtype::DieselNewType;
use serde::de::{Unexpected, Visitor};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Clone, Copy, PartialEq, Eq, Debug, DieselNewType)]
pub struct Id(i64);

impl Id {
  pub async fn generate(snowflake: &SnowflakeGenerator) -> Self {
    Id::from(snowflake.generate_id().await)
  }
}

impl From<i64> for Id {
  fn from(value: i64) -> Self {
    Id(value)
  }
}

fn encode(id: Id) -> Result<String, bs58::encode::Error> {
  let mut encoded = String::new();
  bs58::encode(id.0.to_le_bytes()).onto(&mut encoded)?;

  Ok(encoded)
}

fn decode(str: &str) -> Result<Id, bs58::decode::Error> {
  let mut decoded = [0; 8];
  bs58::decode(str).onto(&mut decoded)?;

  Ok(Id::from(i64::from_le_bytes(decoded)))
}

impl Display for Id {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "{}",
      encode(*self).expect("could not encode ID into base 58")
    )
  }
}

impl From<Id> for String {
  fn from(value: Id) -> Self {
    value.to_string()
  }
}

impl FromStr for Id {
  type Err = bs58::decode::Error;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    decode(s)
  }
}

impl Serialize for Id {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    let string = encode(*self).map_err(|err| {
      serde::ser::Error::custom(format!("could not encode ID into base58: {}", err))
    })?;
    serializer.serialize_str(&string)
  }
}

impl<'de> Deserialize<'de> for Id {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    deserializer.deserialize_str(IdVisitor)
  }
}

struct IdVisitor;

impl<'de> Visitor<'de> for IdVisitor {
  type Value = Id;

  fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
    formatter.write_str("a base58-encoded string")
  }

  fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
  where
    E: serde::de::Error,
  {
    decode(v).map_err(|_| {
      serde::de::Error::invalid_value(Unexpected::Str(v), &"a valid base-58 encoded string")
    })
  }
}
