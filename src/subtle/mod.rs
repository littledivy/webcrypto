use rand::CryptoRng;
use rand::RngCore;

use crate::storage::KeyMaterial;
use crate::storage::KeyStorage;

macro_rules! extend_algorithm {
    (struct $name:ident {
        $(pub $field_name:ident: $field_type:ty,)*
    }) => {
      #[derive(Copy, Clone)]
      pub struct $name {
        pub name: &'static str,
        $(pub $field_name: $field_type,)*
      }

      impl Into<Algorithm> for $name {
        fn into(self) -> Algorithm {
          Algorithm::$name(self)
        }
      }
  };
}

extend_algorithm!(
  struct RsaKeyGenAlgorithm {
    pub modulus_length: usize,
    pub public_exponent: [u8; 3],
  }
);

#[derive(Copy, Clone)]
pub enum Algorithm {
  RsaKeyGenAlgorithm(RsaKeyGenAlgorithm),
}

#[derive(PartialEq, Clone)]
pub enum KeyUsage {
  Encrypt,
  Decrypt,
  Sign,
  Verify,
  WrapKey,
  UnwrapKey,
  DeriveKey,
  DeriveBits,
}

pub enum KeyType {
  Public,
  Private,
  Secret,
}

pub struct CryptoKey<H> {
  /// Determine whether the key can be exportable or not.
  ///
  /// A false value **does not** mean that the key material
  /// is completely secure.
  /// It is **your responsibility** to ensure that in your
  /// key storage.
  pub extractable: bool,
  pub usages: Vec<KeyUsage>,
  pub type_: KeyType,
  pub algorithm: Algorithm,

  handle: H,
}

pub struct CryptoKeyPair<H> {
  pub private_key: CryptoKey<H>,
  pub public_key: CryptoKey<H>,
}

pub enum CryptoKeyOrPair<H> {
  CryptoKey(CryptoKey<H>),
  CryptoKeyPair(CryptoKeyPair<H>),
}

pub struct SubtleCrypto<'a, R: RngCore + CryptoRng, S: KeyStorage<'a>> {
  pub(crate) rng: R,
  storage: S,

  _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a, R: RngCore + CryptoRng, S: KeyStorage<'a>> SubtleCrypto<'a, R, S> {
  pub fn new(rng: R, storage: S) -> Self {
    SubtleCrypto {
      rng,
      storage,
      _marker: std::marker::PhantomData,
    }
  }
}

impl<'a, R: RngCore + CryptoRng, S: KeyStorage<'a>> SubtleCrypto<'a, R, S> {
  pub fn generate_key(
    &mut self,
    algorithm: Algorithm,
    extractable: bool,
    usages: Vec<KeyUsage>,
  ) -> Result<CryptoKeyOrPair<S::Handle>, ()> {
    match algorithm {
      Algorithm::RsaKeyGenAlgorithm(ref rsa_alg) => {
        match rsa_alg.name {
          "RSASSA-PKCS1-v1_5" | "RSA-PSS" => {
            // 1.
            if usages
              .iter()
              .find(|&usage| {
                !(usage == &KeyUsage::Sign || usage == &KeyUsage::Verify)
              })
              .is_some()
            {
              // SyntaxError.
              return Err(());
            }

            // 2.
            let key_data = KeyMaterial(&[0; 10]);

            let handle = self.storage.store(key_data);
            let key_pair = CryptoKeyPair {
              private_key: CryptoKey {
                extractable,
                usages: usages.clone(),
                handle,
                type_: KeyType::Private,
                algorithm,
              },
              public_key: CryptoKey {
                extractable,
                usages,
                handle,
                type_: KeyType::Public,
                algorithm,
              },
            };

            Ok(CryptoKeyOrPair::CryptoKeyPair(key_pair))
          }
          _ => todo!(),
        }
      }
      _ => todo!(),
    }
  }
}
