
pub enum Algorithm {
    RsaKeyGenAlgorithm {
        modulus_length: usize,
        public_exponent: [u8; 3],        
    },
}

pub struct CryptoKey<H> {
    /// Determine whether the key can be exportable or not.
    ///
    /// A false value **does not** mean that the key material 
    /// is completely secure. 
    /// It is **your responsibility** to ensure that in your
    /// key storage.
    pub extractable: bool,

    handle: H,
}
