/// An opaque wrapper to protect direct access
/// to the underlying key material.
#[derive(PartialEq)]
pub struct KeyMaterial<'a>(&'a [u8]);

impl<const N: usize> PartialEq<[u8; N]> for KeyMaterial<'_> {
  fn eq(&self, other: &[u8; N]) -> bool {
    &self.0 == other
  }
}

/// A `KeyStorage` implementation is responsible for providing a way to
/// store and retrieve actual key material in a storage.
///
/// Example for an in-memory store:
/// ```
/// use webcrypto::storage::KeyStorage;
/// use webcrypto::storage::KeyMaterial;
///
/// pub struct InMemoryVault<'a>(Vec<KeyMaterial<'a>>);
///
/// impl<'a> KeyStorage<'a> for InMemoryVault<'a> {
///   type Handle = usize;
///
///   fn store(&mut self, key: KeyMaterial<'a>) -> usize {
///     self.0.push(key);
///     self.0.len() - 1
///   }
///
///   fn get(&self, handle: usize) -> Option<&KeyMaterial<'a>> {
///     self.0.get(handle)
///   }
/// }
/// ```
pub trait KeyStorage<'a> {
  /// The type of the handle to represent a stored key.
  type Handle;

  /// Store the given key in the storage.
  /// Returns a handle that can be used to retrieve the key later.
  fn store(&mut self, key: KeyMaterial<'a>) -> Self::Handle;

  /// Retrieve the key with the given handle.
  fn get(&self, handle: Self::Handle) -> Option<&KeyMaterial<'a>>;
}

#[cfg(test)]
mod tests {
  use super::*;

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

  // Don't do this in your code!
  impl core::fmt::Debug for KeyMaterial<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
      write!(f, "KeyMaterial({:?})", self.0)
    }
  }

  #[test]
  fn test_key_storage() {
    let mut vault = InMemoryVault(Vec::new());
    let key = &[0; 16];
    let material = KeyMaterial(key);

    let handle = vault.store(material);

    assert_eq!(vault.get(handle).unwrap(), key);
  }
}
