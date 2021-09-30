## [wip] webcrypto

Implementation of the [Web Cryptography specification](https://w3c.github.io/webcrypto) in Rust.

This crate hopes to ease interoperability between WASM and native targets.

If you are a browser or just a random person whose in a looking-to-port-JS-code-but-don't-know-how-to-do-that-with-existing-crates-in-the-Rust-ecosystem situation? This crate is for you.

### Usage

Unlike WebCrypto, the crate gives you the resposibility of
storing raw keying material. This is wrapped in the opaque
`KeyMaterial` wrapper type to avoid leakages through bad API usage or backtrace.
You should carefully choose how you store the `KeyMaterial` depending
on your use case.

```rust
/// A simple KeyMaterial storage impl
pub struct InMemoryVault(Vec<KeyMaterial>);

impl KeyStorage for InMemoryVault {

  /// This will be the _hidden_ handle to a `CryptoKey`
  /// In future, this will be required to be serde
  /// serializable.
  type Handle = usize;

  /// Put opaque key material into your backend and return
  /// a handle.
  fn store(&mut self, key: KeyMaterial) -> usize {
    self.0.push(key);
    self.0.len() - 1
  }

  /// Get opaque key material
  fn get(&self, handle: usize) -> Option<&KeyMaterial> {
    self.0.get(handle)
  }
}
```
