//! # Encryption

use serde::{Deserialize, Serialize};

use crate::{PublicKey, SharedSecret};

/// A Receiver (Recipient) is required to decrypt an encrypted message.
pub trait Receiver: Send + Sync {
    /// The Receiver's public key identifier used to identify the recipient in
    /// a multi-recipient payload.
    ///
    /// For example, `did:example:alice#key-id`.
    fn key_id(&self) -> String;

    /// Derive the receiver's shared secret used for decrypting (or direct use)
    /// for the Content Encryption Key.
    ///
    /// `[SecretKey]` wraps the receiver's private key to provide the key
    /// derivation functionality using ECDH-ES. The resultant `[SharedSecret]`
    /// is used in decrypting the JWE ciphertext.
    ///
    /// `[SecretKey]` supports both X25519 and secp256k1 private keys.
    ///
    /// # Errors
    /// LATER: document errors
    ///
    /// # Example
    ///
    /// This example derives a shared secret from an X25519 private key.
    ///
    /// ```rust,ignore
    /// use rand::rngs::OsRng;
    /// use x25519_dalek::{StaticSecret, PublicKey};
    ///
    /// struct KeyStore {
    ///     secret: StaticSecret,
    /// }
    ///
    /// impl KeyStore {
    ///     fn new() -> Self {
    ///         Self {
    ///             secret: StaticSecret::random_from_rng(OsRng),
    ///         }
    ///     }
    /// }
    ///
    /// impl Receiver for KeyStore {
    ///    fn key_id(&self) -> String {
    ///         "did:example:alice#key-id".to_string()
    ///    }
    ///
    /// async fn shared_secret(&self, sender_public: PublicKey) -> anyhow::Result<SharedSecret> {
    ///     let secret_key = SecretKey::from(self.secret.to_bytes());
    ///     secret_key.shared_secret(sender_public)
    /// }
    /// ```
    fn shared_secret(
        &self, sender_public: PublicKey,
    ) -> impl Future<Output = anyhow::Result<SharedSecret>> + Send;
}

/// The algorithm used to perform authenticated content encryption. That is,
/// encrypting the plaintext to produce the ciphertext and the Authentication
/// Tag. MUST be an AEAD algorithm.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum EncAlgorithm {
    /// AES GCM using a 256-bit key.
    #[default]
    #[serde(rename = "A256GCM")]
    A256Gcm,

    /// XChaCha20-Poly1305 is a competitive alternative to AES-256-GCM because
    /// it’s fast and constant-time without hardware acceleration (resistent
    /// to cache-timing attacks). It also has longer nonce length to alleviate
    /// the risk of birthday attacks when nonces are generated randomly.
    #[serde(rename = "XChacha20+Poly1305")]
    XChaCha20Poly1305,
}

/// The algorithm used to encrypt (key encryption) or derive (key agreement)
/// the value of the shared content encryption key (CEK).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum AlgAlgorithm {
    /// Elliptic Curve Diffie-Hellman Ephemeral-Static key agreement using
    /// Concat KDF.
    ///
    /// Uses Direct Key Agreement — a key agreement algorithm is used to agree
    /// upon the CEK value.
    #[default]
    #[serde(rename = "ECDH-ES")]
    EcdhEs,

    /// ECDH-ES using Concat KDF and CEK wrapped with "A256KW".
    ///
    /// Uses Key Agreement with Key Wrapping — a Key Management Mode in which
    /// a key agreement algorithm is used to agree upon a symmetric key used
    /// to encrypt the CEK value to the intended recipient using a symmetric
    /// key wrapping algorithm.
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256Kw,

    /// Elliptic Curve Integrated Encryption Scheme for secp256k1.
    /// Uses AES 256 GCM and HKDF-SHA256.
    #[serde(rename = "ECIES-ES256K")]
    EciesEs256K,
}
