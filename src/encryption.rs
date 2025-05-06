//! # Encryption

use std::fmt::Display;

use aes_gcm::aead::KeyInit; // heapless,
use aes_gcm::{AeadCore, AeadInPlace, Aes256Gcm, Key, Nonce, Tag};
use aes_kw::Kek;
use anyhow::{anyhow, bail};
use chacha20poly1305::XChaCha20Poly1305;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::EphemeralSecret;

use crate::{PUBLIC_KEY_LENGTH, PublicKey, SharedSecret};

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

/// Encrypted content.
#[derive(Clone, Debug, Default)]
pub struct Encrypted {
    /// Initialization vector.
    pub iv: Vec<u8>,

    /// Authentication tag.
    pub tag: Vec<u8>,

    /// Encrypted content.
    pub ciphertext: Vec<u8>,
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

impl Display for EncAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
 
impl EncAlgorithm {
    /// Decrypt a ciphertext using the content encryption key (CEK) and the
    /// initialization vector (IV) and authentication tag.
    ///
    /// # Errors
    /// Will return an error if the lower-level decryption fails.
    pub fn decrypt(
        &self, ciphertext: &[u8], cek: &[u8], iv: &[u8], aad: &[u8], tag: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::A256Gcm => {
                let mut buffer = ciphertext.to_vec();
                let nonce = Nonce::from_slice(iv);
                let tag = Tag::from_slice(tag);
                Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(cek))
                    .decrypt_in_place_detached(nonce, aad, &mut buffer, tag)
                    .map_err(|e| anyhow!("issue decrypting payload: {e}"))?;
                Ok(buffer)
            }
            Self::XChaCha20Poly1305 => {
                // TODO: implement XChaCha20Poly1305 decryption
                bail!("XChaCha20Poly1305 not implemented")
            }
        }
    }

    /// Encrypt a plaintext payload using the content encryption key (CEK) and
    /// the authentication tag.
    ///
    /// # Errors
    /// Will return an error if the lower-level encryption fails.
    pub fn encrypt(
        &self, plaintext: &[u8], cek: &[u8; PUBLIC_KEY_LENGTH], aad: &[u8],
    ) -> anyhow::Result<Encrypted> {
        let mut buffer = plaintext.to_vec();
        let (nonce, tag) = match self {
            Self::A256Gcm => {
                let nonce = Aes256Gcm::generate_nonce(&mut rand::thread_rng());
                let tag = Aes256Gcm::new(cek.into())
                    .encrypt_in_place_detached(&nonce, aad, &mut buffer)
                    .map_err(|e| anyhow!("issue encrypting: {e}"))?;
                (nonce.to_vec(), tag.to_vec())
            }
            Self::XChaCha20Poly1305 => {
                let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
                let tag = XChaCha20Poly1305::new(cek.into())
                    .encrypt_in_place_detached(&nonce, aad, &mut buffer)
                    .map_err(|e| anyhow!("issue encrypting: {e}"))?;
                (nonce.to_vec(), tag.to_vec())
            }
        };
        Ok(Encrypted {
            iv: nonce,
            tag,
            ciphertext: buffer,
        })
    }
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

impl Display for AlgAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl AlgAlgorithm {
    /// Unwrap a content encryption key (CEK) using the shared secret and the
    /// key encryption algorithm.
    ///
    /// # Errors
    /// Will return an error if the lower-level decryption fails or if the
    /// optional parameters are missing when required for a specific algorithm.
    pub fn decrypt(
        &self, shared_secret: &SharedSecret, encrypted_key: Option<&[u8]>,
        init_vector: Option<&[u8]>, tag: Option<&[u8]>,
    ) -> anyhow::Result<[u8; PUBLIC_KEY_LENGTH]> {
        match self {
            Self::EcdhEs => Ok(shared_secret.to_bytes()),
            Self::EcdhEsA256Kw => {
                let Some(encrypted_key) = encrypted_key else {
                    return Err(anyhow!("missing `encrypted_key` required by {self}"));
                };
                Kek::from(shared_secret.to_bytes())
                    .unwrap_vec(encrypted_key)
                    .map_err(|e| anyhow!("issue unwrapping cek: {e}"))?
                    .try_into()
                    .map_err(|_| anyhow!("issue unwrapping cek"))
            }
            Self::EciesEs256K => {
                let Some(encrypted_key) = encrypted_key else {
                    return Err(anyhow!("missing `encrypted_key` required by {self}"));
                };
                let Some(iv) = init_vector else {
                    return Err(anyhow!("missing `init_vector` required by {self}"));
                };
                let Some(tag) = tag else {
                    return Err(anyhow!("missing `tag` required by {self}"));
                };

                let mut buffer = encrypted_key.to_vec();
                let nonce = Nonce::from_slice(iv);
                let tag = Tag::from_slice(tag);

                Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes()))
                    .decrypt_in_place_detached(nonce, &[], &mut buffer, tag)
                    .map_err(|e| anyhow!("issue decrypting CEK: {e}"))?;

                buffer.try_into().map_err(|_| anyhow!("issue unwrapping cek"))
            }
        }
    }

    /// Generate a content encryption key (CEK) using the key encryption
    /// algorithm.
    #[must_use]
    pub fn generate(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        match self {
            Self::EcdhEs => [0; PUBLIC_KEY_LENGTH],
            Self::EcdhEsA256Kw | Self::EciesEs256K => {
                Aes256Gcm::generate_key(&mut rand::thread_rng()).into()
            }
        }
    }

    /// Encrypt the content encryption key (CEK) the recipient's public key.
    ///
    /// # Errors
    /// Will return an error if the lower-level encryption fails.
    pub fn encrypt(
        &self, cek: &[u8; PUBLIC_KEY_LENGTH], recipient_key: &PublicKey,
    ) -> anyhow::Result<EncryptedCek> {
        match self {
            Self::EcdhEs => {
                let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
                let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);
                let recipient_public_key = x25519_dalek::PublicKey::from(*recipient_key);
                let encrypted_key =
                    ephemeral_secret.diffie_hellman(&recipient_public_key).to_bytes();
                Ok(EncryptedCek {
                    encrypted_key: encrypted_key.to_vec(),
                    ephemeral_public: ephemeral_public.into(),
                    iv: None,
                    tag: None,
                })
            }
            Self::EcdhEsA256Kw => {
                let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
                let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);
                let recipient_public_key = x25519_dalek::PublicKey::from(*recipient_key);
                let shared_secret =
                    ephemeral_secret.diffie_hellman(&recipient_public_key).to_bytes();
                let encrypted_key = Kek::from(shared_secret)
                    .wrap_vec(cek)
                    .map_err(|e| anyhow!("issue wrapping cek: {e}"))?;
                Ok(EncryptedCek {
                    encrypted_key,
                    ephemeral_public: ephemeral_public.into(),
                    iv: None,
                    tag: None,
                })
            }
            Self::EciesEs256K => {
                let (ephemeral_secret, ephemeral_public) = ecies::utils::generate_keypair();
                let recipient_public_key = ecies::PublicKey::try_from(*recipient_key)?;
                let shared_secret =
                    ecies::utils::encapsulate(&ephemeral_secret, &recipient_public_key)
                        .map_err(|e| anyhow!("issue encapsulating: {e}"))?;
                let iv = Aes256Gcm::generate_nonce(&mut OsRng);
                let mut encrypted_key = *cek;
                let tag = Aes256Gcm::new(&shared_secret.into())
                    .encrypt_in_place_detached(&iv, &[], &mut encrypted_key)
                    .map_err(|e| anyhow!("issue encrypting: {e}"))?;
                let ephemeral_public = ephemeral_public.serialize(); // 65 bytes
                Ok(EncryptedCek {
                    encrypted_key: encrypted_key.to_vec(),
                    ephemeral_public: ephemeral_public.into(),
                    iv: Some(iv.to_vec()),
                    tag: Some(tag.to_vec()),
                })
            }
        }
    }
}

/// The output from encrypting the content encryption key (CEK).
pub struct EncryptedCek {
    /// Encrypted CEK.
    pub encrypted_key: Vec<u8>,
    /// Ephemeral public key.
    pub ephemeral_public: PublicKey,
    /// Initialization vector if applicable to the algorithm.
    pub iv: Option<Vec<u8>>,
    /// Authentication tag if applicable to the algorithm.
    pub tag: Option<Vec<u8>>,
}
