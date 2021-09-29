pub mod storage;
pub mod subtle;

use crate::storage::KeyStorage;
use crate::subtle::SubtleCrypto;

use rand::CryptoRng;
use rand::RngCore;

pub use rand;

/// A WebCrypto context with a cryptographically
/// secure RNG.
///
/// An application may use multiple contexts
/// the operation is not expensive.
pub struct Context<'a, R: RngCore + CryptoRng, S: KeyStorage<'a>> {
  pub subtle: SubtleCrypto<'a, R, S>,
}

impl<'a, R: RngCore + CryptoRng, S: KeyStorage<'a>> Context<'a, R, S> {
  pub fn new(rng: R, storage: S) -> Self {
    let subtle = SubtleCrypto::new(rng, storage);
    Context { subtle }
  }
}

impl<'a, R: RngCore + CryptoRng, S: KeyStorage<'a>> Context<'a, R, S> {
  pub fn get_random_values(&mut self, slice: &mut [u8]) {
    if slice.len() > 65536 {
      // QuotaExceededError
    }

    self.subtle.rng.fill_bytes(slice);
  }

  pub fn random_uuid(&mut self) -> String {
    let mut bytes = [0; 16];
    self.subtle.rng.fill_bytes(&mut bytes);

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
  use storage::KeyMaterial;
  use storage::KeyStorage;

  // FIXME: Duplicate code from src/storage.rs
  pub struct InMemoryVault<'a>(Vec<KeyMaterial<'a>>);

  impl<'a> KeyStorage<'a> for InMemoryVault<'a> {
    type Handle = usize;

    fn store(&mut self, key: KeyMaterial<'a>) -> usize {
      self.0.push(key);
      self.0.len() - 1
    }

    fn get(&self, handle: usize) -> Option<&KeyMaterial<'a>> {
      self.0.get(handle)
    }
  }

  #[test]
  fn test_get_random_values() {
    let mut ctx = Context::new(rand::thread_rng(), InMemoryVault(vec![]));

    let mut bytes = [0u8; 65535];
    ctx.get_random_values(&mut bytes);
  }

  #[test]
  fn test_random_uuid() {
    let mut ctx = Context::new(rand::thread_rng(), InMemoryVault(vec![]));

    let uuid = ctx.random_uuid();
    assert_eq!(uuid.len(), 36);
  }

  #[test]
  fn test_generate_key() {
    let mut ctx = Context::new(rand::thread_rng(), InMemoryVault(vec![]));

    let key = ctx.subtle.generate_key(
      &subtle::Algorithm::RsaKeyGenAlgorithm(subtle::RsaKeyGenAlgorithm {
        modulus_length: 2048,
        public_exponent: [0x01, 0x00, 0x01],
        name: "RSA-PSS",
      }),
      true,
      vec![],
    );
  }
}
