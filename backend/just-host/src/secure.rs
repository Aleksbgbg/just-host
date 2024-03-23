use rand_core::{OsRng, RngCore};

pub struct Bytes(pub usize);

pub fn random_bytes(Bytes(len): Bytes) -> Result<Vec<u8>, rand_core::Error> {
  let mut bytes = vec![0; len];
  OsRng.try_fill_bytes(&mut bytes)?;
  Ok(bytes)
}
