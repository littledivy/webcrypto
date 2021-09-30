use rand::CryptoRng;
use rand::RngCore;

use rsa::pkcs1::ToRsaPrivateKey;
use rsa::BigUint;
use rsa::RsaPrivateKey;

use crate::storage::KeyMaterial;
use crate::storage::KeyStorage;

macro_rules! impl_algorithm {
  (struct $name:ident {
        $($field_name:ident: $field_type:ty,)*
  }) => {
    #[derive(Copy, Clone)]
    pub struct $name {
      pub name: &'static str,
      $(pub $field_name: $field_type,)*
    }
  };
  (struct $name:ident {
    $($field_name:ident: $field_type:ty,)*
  }, $counterpart: ident) => {
    #[derive(Copy, Clone)]
    pub struct $name {
      pub name: &'static str,
      $(pub $field_name: $field_type,)*
    }

    impl Into<KeyGenParams> for $name {
      fn into(self) -> KeyGenParams {
        KeyGenParams::$name(self)
      }
    }

    #[derive(Copy, Clone)]
    pub struct $counterpart {
      pub name: &'static str,
      $(pub $field_name: $field_type,)*
    }

    impl Into<Algorithm> for $counterpart {
      fn into(self) -> Algorithm {
        Algorithm::$counterpart(self)
      }
    }

    impl Into<Algorithm> for $name {
      fn into(self) -> Algorithm {
        Algorithm::$counterpart($counterpart {
          name: self.name,
          $($field_name: self.$field_name,)*
        })
      }
    }
 };
}

#[non_exhaustive]
#[derive(Copy, Clone)]
pub enum NamedCurve {
  /// NIST P-256 (secp256r1)
  P256,
  /// NIST P-384 (secp384r1)
  P384,
  /// NIST P-521 (secp512r1)
  P521,
}

impl_algorithm!(
  struct HashAlgorithmIdentifer {}
);

impl_algorithm!(
  struct RsaKeyGenParams {
    modulus_length: usize,
    public_exponent: [u8; 3],
  },
  RsaKeyAlgorithm
);

impl_algorithm!(
  struct RsaHashedKeyGenParams {
    hash: HashAlgorithmIdentifer,
    modulus_length: usize,
    public_exponent: [u8; 3],
  },
  RsaHashedKeyAlgorithm
);

impl_algorithm!(
  struct EcKeyGenParams {
    named_curve: NamedCurve,
  },
  EcKeyAlgorithm
);

impl_algorithm!(
  struct AesKeyGenParams {
    length: usize,
  },
  AesKeyAlgorithm
);

impl_algorithm!(
  struct HmacKeyGenParams {
    hash: HashAlgorithmIdentifer,
    length: usize,
  },
  HmacKeyAlgorithm
);

#[derive(Copy, Clone)]
pub enum KeyGenParams {
  RsaKeyGenParams(RsaKeyGenParams),
  RsaHashedKeyGenParams(RsaHashedKeyGenParams),
  EcKeyGenParams(EcKeyGenParams),
  AesKeyGenParams(AesKeyGenParams),
  HmacKeyGenParams(HmacKeyGenParams),
}

#[derive(Copy, Clone)]
pub enum Algorithm {
  RsaKeyAlgorithm(RsaKeyAlgorithm),
  RsaHashedKeyAlgorithm(RsaHashedKeyAlgorithm),
  EcKeyAlgorithm(EcKeyAlgorithm),
  AesKeyAlgorithm(AesKeyAlgorithm),
  HmacKeyAlgorithm(HmacKeyAlgorithm),
}

impl Into<Algorithm> for KeyGenParams {
  fn into(self) -> Algorithm {
    match self {
      KeyGenParams::RsaKeyGenParams(params) => params.into(),
      KeyGenParams::RsaHashedKeyGenParams(params) => params.into(),
      KeyGenParams::EcKeyGenParams(params) => params.into(),
      KeyGenParams::AesKeyGenParams(params) => params.into(),
      KeyGenParams::HmacKeyGenParams(params) => params.into(),
    }
  }
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

pub struct SubtleCrypto<R: RngCore + CryptoRng, S: KeyStorage> {
  pub(crate) rng: R,
  storage: S,
}

impl<R: RngCore + CryptoRng, S: KeyStorage> SubtleCrypto<R, S> {
  pub fn new(rng: R, storage: S) -> Self {
    SubtleCrypto { rng, storage }
  }
}

impl<R: RngCore + CryptoRng, S: KeyStorage> SubtleCrypto<R, S> {
  pub fn generate_key(
    &mut self,
    algorithm: KeyGenParams,
    extractable: bool,
    usages: Vec<KeyUsage>,
  ) -> Result<CryptoKeyOrPair<S::Handle>, ()> {
    match algorithm {
      KeyGenParams::RsaHashedKeyGenParams(ref rsa_alg) => {
        match rsa_alg.name {
          "RSASSA-PKCS1-v1_5" | "RSA-PSS" | "RSA-OAEP" => {
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
            let exp = BigUint::from_bytes_be(&rsa_alg.public_exponent);
            let p_key = RsaPrivateKey::new_with_exp(
              &mut self.rng,
              rsa_alg.modulus_length,
              &exp,
            )
            .map_err(|_| ())?;

            let pkcs1 = p_key.to_pkcs1_der().map_err(|_| ())?;

            let handle =
              self.storage.store(KeyMaterial(pkcs1.as_ref().to_vec()));

            let key_pair = CryptoKeyPair {
              private_key: CryptoKey {
                extractable,
                usages: usages.clone(),
                handle,
                type_: KeyType::Private,
                algorithm: algorithm.into(),
              },
              public_key: CryptoKey {
                extractable,
                usages,
                handle,
                type_: KeyType::Public,
                algorithm: algorithm.into(),
              },
            };

            Ok(CryptoKeyOrPair::CryptoKeyPair(key_pair))
          }
          _ => todo!(),
        }
      }
      KeyGenParams::AesKeyGenParams(ref aes_alg) => match aes_alg.name {
        "AES-CTR" | "AES-CBC" | "AES-GCM" | "AES-KW" => {
          let mut key_data = vec![0u8; aes_alg.length];
          self.rng.fill_bytes(&mut key_data);
          let handle = self.storage.store(KeyMaterial(key_data));

          let key = CryptoKey {
            extractable,
            usages,
            handle,
            type_: KeyType::Secret,
            algorithm: algorithm.into(),
          };

          Ok(CryptoKeyOrPair::CryptoKey(key))
        }
        _ => todo!(),
      },
      KeyGenParams::HmacKeyGenParams(ref hmac_alg) => {
        match hmac_alg.name {
          "HMAC" => {
            // TODO: length is optional, default to digest block length
            let mut key_data = vec![0u8; hmac_alg.length];
            self.rng.fill_bytes(&mut key_data);

            let handle = self.storage.store(KeyMaterial(key_data));

            let key = CryptoKey {
              extractable,
              usages,
              handle,
              type_: KeyType::Secret,
              algorithm: algorithm.into(),
            };

            Ok(CryptoKeyOrPair::CryptoKey(key))
          }
          _ => todo!(),
        }
      }
      _ => todo!(),
    }
  }
}
