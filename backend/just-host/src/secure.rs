use base64::engine::general_purpose;
use base64::Engine;
use rand_core::{OsRng, RngCore};

pub struct Bytes(pub usize);

pub fn random_bytes(Bytes(len): Bytes) -> Result<Vec<u8>, rand_core::Error> {
  let mut bytes = vec![0; len];
  OsRng.try_fill_bytes(&mut bytes)?;
  Ok(bytes)
}

pub fn random_string_base64(len: Bytes) -> Result<String, rand_core::Error> {
  Ok(general_purpose::STANDARD.encode(random_bytes(len)?))
}
