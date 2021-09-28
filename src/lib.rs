pub mod storage;
pub mod subtle;

use rand::CryptoRng;
use rand::RngCore;

pub use rand;

/// A WebCrypto context with a cryptographically
/// secure RNG.
///
/// An application may use multiple contexts
/// the operation is not expensive.
pub struct Context<R: RngCore + CryptoRng>(R);

impl<R: RngCore + CryptoRng> Context<R> {
  pub fn new(rng: R) -> Self {
    Context(rng)
  }
}

impl<R: RngCore + CryptoRng> Context<R> {
  pub fn get_random_values(&mut self, slice: &mut [u8]) {
    if slice.len() > 65536 {
      // QuotaExceededError
    }

    self.0.fill_bytes(slice);
  }

  pub fn random_uuid(&mut self) -> String {
    let mut bytes = [0; 16];
    self.0.fill_bytes(&mut bytes);

    let uuid = uuid::Builder::from_bytes(bytes)
      .set_variant(uuid::Variant::RFC4122)
      .set_version(uuid::Version::Random)
      .build();

    uuid.to_string()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_get_random_values() {
    let mut ctx = Context::new(rand::thread_rng());

    let mut bytes = [0u8; 65535];
    ctx.get_random_values(&mut bytes);
  }

  #[test]
  fn test_random_uuid() {
    let mut ctx = Context::new(rand::thread_rng());

    let uuid = ctx.random_uuid();
    assert_eq!(uuid.len(), 36);
  }
}
