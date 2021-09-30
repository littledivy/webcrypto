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
pub struct Context<R: RngCore + CryptoRng, S: KeyStorage> {
  pub subtle: SubtleCrypto<R, S>,
}

impl<R: RngCore + CryptoRng, S: KeyStorage> Context<R, S> {
  pub fn new(rng: R, storage: S) -> Self {
    let subtle = SubtleCrypto::new(rng, storage);
    Context { subtle }
  }
}

impl<R: RngCore + CryptoRng, S: KeyStorage> Context<R, S> {
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
  pub struct InMemoryVault(Vec<KeyMaterial>);

  impl KeyStorage for InMemoryVault {
    type Handle = usize;

    fn store(&mut self, key: KeyMaterial) -> usize {
      self.0.push(key);
      self.0.len() - 1
    }

    fn get(&self, handle: usize) -> Option<&KeyMaterial> {
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

    let key = ctx
      .subtle
      .generate_key(
        subtle::RsaHashedKeyGenParams {
          modulus_length: 2048,
          public_exponent: [0x01, 0x00, 0x01],
          name: "RSA-PSS",
          hash: subtle::HashAlgorithmIdentifer { name: "SHA-256" },
        }
        .into(),
        true,
        vec![],
      )
      .unwrap();

    if let subtle::CryptoKeyOrPair::CryptoKeyPair(key) = key {
      assert_eq!(key.public_key.extractable, true);
      assert_eq!(key.private_key.extractable, true);
    } else {
      panic!("Expected CryptoKeyPair");
    }
  }

  #[test]
  fn test_sign_verify() {
    let rng = rand::rngs::OsRng;
    let mut ctx = Context::new(rng, InMemoryVault(vec![]));

    let key = ctx
      .subtle
      .generate_key(
        subtle::RsaHashedKeyGenParams {
          modulus_length: 2048,
          public_exponent: [0x01, 0x00, 0x01],
          name: "RSA-PSS",
          hash: subtle::HashAlgorithmIdentifer { name: "SHA-256" },
        }
        .into(),
        true,
        vec![],
      )
      .unwrap();

    if let subtle::CryptoKeyOrPair::CryptoKeyPair(key) = key {
      assert_eq!(key.public_key.extractable, true);
      assert_eq!(key.private_key.extractable, true);

      let sig = ctx
        .subtle
        .sign(
          subtle::SignParams::RsaPssParams (subtle::RsaPssParams { name: "RSA-PSS", salt_length: 20 }),
          &key.private_key,
          b"Hello, world!",
        )
        .unwrap();

      let verified = ctx
        .subtle
        .verify(
          subtle::SignParams::RsaPssParams (subtle::RsaPssParams { name: "RSA-PSS", salt_length: 20 }),
          &key.public_key,
          &sig,
          b"Hello, world!",
        )
        .unwrap();
      assert_eq!(verified, true);
    } else {
      panic!("Expected CryptoKeyPair");
    }
  }
}
