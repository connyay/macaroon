//! RustCrypto cryptographic backend implementation
//!
//! Uses pure Rust implementations from the RustCrypto project,
//! compatible with WebAssembly and other constrained environments.

use super::MacaroonKey;
use crate::Result;
use crate::error::MacaroonError;
use crypto_secretbox::{
    Key as AeadKey, Nonce, XSalsa20Poly1305,
    aead::{Aead, KeyInit},
};
use hmac::{Hmac, Mac};
use log::error;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub(crate) struct RustCryptoBackend;

impl RustCryptoBackend {
    pub fn hmac<T, U>(key: &T, text: &U) -> MacaroonKey
    where
        T: AsRef<[u8; 32]> + ?Sized,
        U: AsRef<[u8]> + ?Sized,
    {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key.as_ref())
            .expect("HMAC can take key of any size");
        mac.update(text.as_ref());
        let result = mac.finalize().into_bytes();

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&result);
        MacaroonKey::from(key_bytes)
    }

    pub fn hmac2<T, U>(key: &T, text1: &U, text2: &U) -> MacaroonKey
    where
        T: AsRef<[u8; 32]> + ?Sized,
        U: AsRef<[u8]> + ?Sized,
    {
        let tmp1 = Self::hmac(key, text1);
        let tmp2 = Self::hmac(key, text2);
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key.as_ref())
            .expect("HMAC can take key of any size");
        mac.update(tmp1.as_ref());
        mac.update(tmp2.as_ref());
        let result = mac.finalize().into_bytes();

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&result);
        MacaroonKey::from(key_bytes)
    }

    pub fn encrypt_key<T>(key: &T, plaintext: &T) -> Result<Vec<u8>>
    where
        T: AsRef<[u8; 32]> + ?Sized,
    {
        let cipher = XSalsa20Poly1305::new(AeadKey::from_slice(key.as_ref()));

        // Random 24-byte nonce. XSalsa20-Poly1305's 192-bit nonce makes
        // collision under random generation negligible (birthday bound 2^96).
        let mut nonce_bytes = [0u8; 24];
        Self::fill_random(&mut nonce_bytes)?;
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref() as &[u8])
            .map_err(|_| MacaroonError::CryptoError("encryption failed"))?;

        // nonce || ciphertext (NaCl secretbox wire format, matches libmacaroons)
        let mut result = Vec::with_capacity(24 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt_key<T, U>(key: &T, data: &U) -> Result<MacaroonKey>
    where
        T: AsRef<[u8; 32]> + ?Sized,
        U: AsRef<[u8]> + ?Sized,
    {
        let raw_data: &[u8] = data.as_ref();

        // XSalsa20Poly1305: 24 byte nonce + 16 byte tag = minimum 40 bytes
        const NONCE_SIZE: usize = 24;
        const TAG_SIZE: usize = 16;

        if raw_data.len() < NONCE_SIZE + TAG_SIZE {
            error!(
                "crypto::decrypt: Encrypted data too short (len={})",
                raw_data.len()
            );
            return Err(MacaroonError::CryptoError("encrypted data too short"));
        }

        let nonce = Nonce::from_slice(&raw_data[..NONCE_SIZE]);
        let ciphertext = &raw_data[NONCE_SIZE..];

        let cipher = XSalsa20Poly1305::new(AeadKey::from_slice(key.as_ref()));

        match cipher.decrypt(nonce, ciphertext) {
            Ok(plaintext) => {
                if plaintext.len() != 32 {
                    return Err(MacaroonError::CryptoError(
                        "decrypted key has wrong length (expected 32 bytes)",
                    ));
                }

                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&plaintext);
                Ok(MacaroonKey::from(key_bytes))
            }
            Err(_) => {
                error!(
                    "crypto::decrypt: Decryption failed (data len={})",
                    raw_data.len()
                );
                Err(MacaroonError::CryptoError("failed to decrypt ciphertext"))
            }
        }
    }

    pub fn generate_random_key() -> Result<MacaroonKey> {
        let mut key_bytes = [0u8; 32];
        Self::fill_random(&mut key_bytes)?;
        Ok(MacaroonKey::from(key_bytes))
    }

    fn fill_random(buf: &mut [u8]) -> Result<()> {
        // `getrandom` works on both native (via OS RNG) and
        // wasm32-unknown-unknown with the `wasm_js` feature enabled (via
        // `crypto.getRandomValues`). A failure here is propagated up instead
        // of aborting, which matters on WASM: a sandboxed iframe with no
        // `crypto` global would otherwise crash the whole module.
        getrandom::fill(buf).map_err(|_| MacaroonError::RngError("getrandom failed"))
    }
}

#[cfg(test)]
mod test {
    use super::{MacaroonKey, RustCryptoBackend};

    #[test]
    fn test_encrypt_decrypt() {
        let mut secret_bytes = [0u8; 32];
        secret_bytes[..24].copy_from_slice(b"This is my encrypted key");
        let secret = MacaroonKey::from(secret_bytes);

        let mut key_bytes = [0u8; 32];
        key_bytes[..21].copy_from_slice(b"This is my secret key");
        let key = MacaroonKey::from(key_bytes);

        let encrypted = RustCryptoBackend::encrypt_key(&key, &secret).unwrap();
        let decrypted = RustCryptoBackend::decrypt_key(&key, &encrypted).unwrap();
        assert_eq!(secret, decrypted);
    }

    #[test]
    fn test_hmac() {
        let key = MacaroonKey::from([1u8; 32]);
        let message = b"test message";

        let result1 = RustCryptoBackend::hmac(&key, message);
        let result2 = RustCryptoBackend::hmac(&key, message);

        // HMAC should be deterministic
        assert_eq!(result1, result2);

        // Should be different with different key
        let key2 = MacaroonKey::from([2u8; 32]);
        let result3 = RustCryptoBackend::hmac(&key2, message);
        assert_ne!(result1, result3);
    }

    #[test]
    fn test_hmac2() {
        let key = MacaroonKey::from([1u8; 32]);
        let text1 = b"first";
        let text2 = b"second";

        let result = RustCryptoBackend::hmac2(&key, text1 as &[u8], text2 as &[u8]);

        // Should be same as HMAC of concatenated individual HMACs
        let tmp1 = RustCryptoBackend::hmac(&key, text1);
        let tmp2 = RustCryptoBackend::hmac(&key, text2);
        let tmp = [tmp1.as_ref() as &[u8], tmp2.as_ref() as &[u8]].concat();
        let expected = RustCryptoBackend::hmac(&key, &tmp);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_random_key_generation() {
        let key1 = RustCryptoBackend::generate_random_key().unwrap();
        let key2 = RustCryptoBackend::generate_random_key().unwrap();

        // Keys should be different
        assert_ne!(key1, key2);

        // Keys should not be all zeros
        assert_ne!(key1.as_ref() as &[u8; 32], &[0u8; 32]);
        assert_ne!(key2.as_ref() as &[u8; 32], &[0u8; 32]);
    }
}
