//! Basic key store for testing

mod blockstore;

use std::fmt::Display;

use blockstore::Mockstore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// A type of key to be added to the key store and used for either signing or
/// encrypting data.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum KeyType {
    /// A key for signing data with the ED25519 algorithm.
    EdDSA,

    /// A key for encrypting data with the X25519 algorithm.
    X25519,

    /// A key for encrypting data with the ES256k algorithm.
    Es256k,
}

impl KeyType {
    /// Generate a new key for the given key type.
    pub fn generate(&self) -> Vec<u8> {
        match self {
            KeyType::EdDSA => {
                let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
                signing_key.as_bytes().to_vec()
            }
            KeyType::X25519 => {
                let secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
                secret_key.to_bytes().to_vec()
            }
            KeyType::Es256k => {
                let (secret_key, _) = ecies::utils::generate_keypair();
                secret_key.serialize().to_vec()
            }
        }
    }
}

impl Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A simple keyring that stores secret keys and their usage types in memory.
///
/// Suitable for testing only.
#[derive(Clone)]
pub struct Keyring {
    blockstore: Mockstore,
}

impl Keyring {
    // Create a new keyring.
    #[must_use]
    pub fn new() -> Self {
        Self {
            blockstore: Mockstore::new(),
        }
    }

    // Add a newly generated key and a corresponding next key to the keyring.
    pub async fn add_key(&mut self, key_type: &KeyType, id: impl ToString) -> anyhow::Result<()> {
        let id = id.to_string();
        let key_bytes = key_type.generate();
        self.blockstore.put("test", &key_type.to_string(), &id, &key_bytes).await?;
        let next_key_bytes = key_type.generate();
        self.blockstore
            .put("test", &key_type.to_string(), &format!("next_{id}"), &next_key_bytes)
            .await?;

        todo!();
    }
}
