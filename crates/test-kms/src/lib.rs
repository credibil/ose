//! Basic key store for testing

mod blockstore;

use std::fmt::Display;

use anyhow::{anyhow, bail};
use blockstore::Mockstore;
use credibil_ose::{PublicKey, PUBLIC_KEY_LENGTH};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// A type of key to be added to the key store and used for either signing or
/// encrypting data.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
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
        match self {
            KeyType::EdDSA => write!(f, "EdDSA"),
            KeyType::X25519 => write!(f, "X25519"),
            KeyType::Es256k => write!(f, "ES256K"),
        }
    }
}

/// Key as serialized and stored to the blob store.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StoredKey {
    /// The key type.
    pub key_type: KeyType,

    /// The key itself (private key).
    pub key: Vec<u8>,

    /// The next (private) key to use.
    pub next_key: Vec<u8>,
}

impl StoredKey {
    /// Serialize the key to a byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).unwrap();
        buf
    }

    /// Deserialize a byte array to a `StoredKey`.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        ciborium::from_reader(bytes).map_err(Into::into)
    }
}

/// An index of keys in the keyring.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
pub struct IndexEntry {
    /// Keyring owner.
    pub owner: String,

    /// Keyring partition.
    pub partition: KeyType,

    /// Name or ID of the key.
    pub id: String,
}

/// Keyring index.
pub struct KeyringIndex(Vec<IndexEntry>);

impl KeyringIndex {
    /// Create a new keyring index.
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Add a new entry to the keyring index.
    pub fn add(&mut self, entry: IndexEntry) {
        self.0.push(entry);
    }

    /// Remove an entry from the keyring index.
    pub fn remove(&mut self, entry: &IndexEntry) {
        self.0.retain(|e| e != entry);
    }

    /// Serialize the keyring index to a byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(&self.0, &mut buf).unwrap();
        buf
    }

    /// Deserialize a byte array to a `KeyringIndex`.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let entries: Vec<IndexEntry> = ciborium::from_reader(bytes)?;
        Ok(Self(entries))
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
    /// Create a new keyring and initialize a block for key indexes.
    ///
    /// # Errors
    /// Will return an error if storage of an index block fails.
    #[must_use]
    pub async fn new() -> anyhow::Result<Self> {
        let blockstore = Mockstore::new();
        let index = KeyringIndex::new();
        let index_bytes = index.to_bytes();
        blockstore.put("test", "keyring", "index", &index_bytes).await?;

        Ok(Self { blockstore })
    }

    /// Add a newly generated key and a corresponding next key to the keyring.
    ///
    /// # Errors
    /// Will return an error if the storage fails or the index cannot be
    /// updated.
    pub async fn add(&mut self, key_type: &KeyType, id: impl ToString) -> anyhow::Result<()> {
        let id = id.to_string();
        let key_bytes = key_type.generate();
        let next_key_bytes = key_type.generate();
        let stored_key = StoredKey {
            key_type: key_type.clone(),
            key: key_bytes.clone(),
            next_key: next_key_bytes.clone(),
        };
        self.blockstore.put("test", &key_type.to_string(), &id, &stored_key.to_bytes()).await?;

        // Update the index.
        self.add_index_entry(key_type, id).await?;

        Ok(())
    }

    /// Replace a key in the keyring with a new one. Generates a corresponding
    /// next key.
    ///
    /// # Errors
    /// Will return an error if the requested key does not exist in the keyring.
    /// (Use `add` instead).
    pub async fn replace(&mut self, key_type: &KeyType, id: impl ToString) -> anyhow::Result<()> {
        // Check for existence of the key
        let exists = self.blockstore.exists("test", &key_type.to_string(), &id.to_string()).await?;
        if !exists {
            bail!("key not found");
        }
        self.add(key_type, id).await
    }

    /// Rotate all keys in the keyring.
    ///
    /// # Errors
    /// Will return an error if the storage fails, including retrieving the
    /// index.
    pub async fn rotate_all(&mut self) -> anyhow::Result<()> {
        let index_bytes = self
            .blockstore
            .get("test", "keyring", "index")
            .await?
            .ok_or(anyhow!("index not found"))?;
        let mut index = KeyringIndex::from_bytes(&index_bytes)?;
        for entry in &mut index.0 {
            let key_type = &entry.partition;
            let id = &entry.id;

            let current_key = self
                .blockstore
                .get("test", &key_type.to_string(), id)
                .await?
                .ok_or(anyhow!("key not found"))?;
            let current_key = StoredKey::from_bytes(&current_key)?;
            let next_key = key_type.generate();
            let new_key = StoredKey {
                key_type: key_type.clone(),
                key: current_key.next_key,
                next_key,
            };
            self.blockstore.put("test", &key_type.to_string(), id, &new_key.to_bytes()).await?;
        }
        Ok(())
    }

    /// Rotate a key in the keyring.
    ///
    /// # Errors
    /// Will return an error if the requested key does not exist in the keyring.
    pub async fn rotate(&mut self, key_type: &KeyType, id: impl ToString) -> anyhow::Result<()> {
        let current_key = self
            .blockstore
            .get("test", &key_type.to_string(), &id.to_string())
            .await?
            .ok_or(anyhow!("key not found"))?;
        let current_key = StoredKey::from_bytes(&current_key)?;
        let next_key = key_type.generate();
        let new_key = StoredKey {
            key_type: key_type.clone(),
            key: current_key.next_key,
            next_key,
        };
        self.blockstore
            .put("test", &key_type.to_string(), &id.to_string(), &new_key.to_bytes())
            .await
    }

    /// Remove a key from the keyring.
    ///
    /// # Errors
    /// Will return an error if the requested key cannot be removed from storage
    /// or the index cannot be updated.
    pub async fn remove(&mut self, key_type: &KeyType, id: impl ToString) -> anyhow::Result<()> {
        self.blockstore.delete("test", &key_type.to_string(), &id.to_string()).await?;
        self.remove_index_entry(key_type, id).await
    }

    /// Get a public key from the keyring with the given type and ID.
    ///
    /// # Errors
    /// Will return an error if the requested key cannot be retrieved from
    /// storage or if the public key cannot be inferred from the private key.
    pub async fn public_key(
        &mut self, key_type: &KeyType, id: impl ToString,
    ) -> anyhow::Result<PublicKey> {
        let stored_key = self
            .blockstore
            .get("test", &key_type.to_string(), &id.to_string())
            .await?
            .ok_or(anyhow!("key not found"))?;
        let stored_key = StoredKey::from_bytes(&stored_key)?;
        match key_type {
            KeyType::EdDSA => {
                let signing_key_bytes: [u8; PUBLIC_KEY_LENGTH] = stored_key
                    .key
                    .try_into()
                    .map_err(|_| anyhow!("cannot convert stored vec to slice"))?;
                let signing_key = ed25519_dalek::SigningKey::try_from(&signing_key_bytes)?;
                let verifying_key = signing_key.verifying_key();    
                let public_key =
                    x25519_dalek::PublicKey::from(verifying_key.to_montgomery().to_bytes());
                Ok(PublicKey::from(public_key))
            }
            KeyType::X25519 => {
                let secret_key_bytes: [u8; PUBLIC_KEY_LENGTH] = stored_key
                    .key
                    .try_into()
                    .map_err(|_| anyhow!("cannot convert stored vec to slice"))?;
                let secret_key = x25519_dalek::StaticSecret::from(secret_key_bytes);
                let public_key = x25519_dalek::PublicKey::from(&secret_key);
                Ok(PublicKey::from(public_key))
            }
            KeyType::Es256k => {
                let secret_key_bytes: [u8; PUBLIC_KEY_LENGTH] = stored_key
                    .key
                    .try_into()
                    .map_err(|_| anyhow!("cannot convert stored vec to slice"))?;
                let secret_key = ecies::SecretKey::parse(&secret_key_bytes)
                    .map_err(|_| anyhow!("cannot deserialize secret key"))?;
                let public_key = ecies::PublicKey::from_secret_key(&secret_key);
                Ok(PublicKey::from(public_key))
            }
        }
    }

    /// Add an entry to the keyring index.
    ///
    /// # Errors
    /// Will return an error if the index cannot be updated.
    async fn add_index_entry(
        &mut self, key_type: &KeyType, id: impl ToString,
    ) -> anyhow::Result<()> {
        let entry = IndexEntry {
            owner: "test".to_string(),
            partition: key_type.clone(),
            id: id.to_string(),
        };
        let mut index = KeyringIndex::from_bytes(
            &self
                .blockstore
                .get("test", "keyring", "index")
                .await?
                .ok_or(anyhow!("index not found"))?,
        )?;
        index.add(entry);
        self.blockstore.put("test", "keyring", "index", &index.to_bytes()).await
    }

    /// Remove an entry from the keyring index.
    ///
    /// # Errors
    /// Will return an error if the index cannot be updated.
    async fn remove_index_entry(
        &mut self, key_type: &KeyType, id: impl ToString,
    ) -> anyhow::Result<()> {
        let entry = IndexEntry {
            owner: "test".to_string(),
            partition: key_type.clone(),
            id: id.to_string(),
        };
        let mut index = KeyringIndex::from_bytes(
            &self
                .blockstore
                .get("test", "keyring", "index")
                .await?
                .ok_or(anyhow!("index not found"))?,
        )?;
        index.remove(&entry);
        self.blockstore.put("test", "keyring", "index", &index.to_bytes()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn keyring_crud() {
        let mut keyring = Keyring::new().await.expect("keyring created");

        // Create an Ed25519 key
        let key_type = KeyType::EdDSA;
        let id = "one";
        keyring.add(&key_type, id).await.expect("Ed25519 key added");

        // Get the public key for the Ed25519 key.
        let _ = keyring.public_key(&key_type, id).await.expect("Ed25519 key retrieved");

        // Create an X25519 key
        let key_type = KeyType::X25519;
        let id = "two";
        keyring.add(&key_type, id).await.expect("key added");

        // Get the public key for the X25519 key.
        let _ = keyring.public_key(&key_type, id).await.expect("X25519 key retrieved");

        // Create an ES256k key
        let key_type = KeyType::Es256k;
        let id = "three";
        keyring.add(&key_type, id).await.expect("key added");

        // Get the public key for the ES256k key.
        let _ = keyring.public_key(&key_type, id).await.expect("ES256k key retrieved");

        // Rotate all the keys
        keyring.rotate_all().await.expect("all keys rotated");

        // Rotate the Ed25519 key
        let key_type = KeyType::EdDSA;
        let id = "one";
        keyring.rotate(&key_type, id).await.expect("Ed25519 key rotated");

        // Replace the X25519 key
        let key_type = KeyType::X25519;
        let id = "two";
        keyring.replace(&key_type, id).await.expect("X25519 key replaced");

        // Remove the Ed25519 key
        let key_type = KeyType::EdDSA;
        let id = "one";
        keyring.remove(&key_type, id).await.expect("Ed25519 key removed");

        // Remove the X25519 key
        let key_type = KeyType::X25519;
        let id = "two";
        keyring.remove(&key_type, id).await.expect("X25519 key removed");

        // Remove the ES256k key
        let key_type = KeyType::Es256k;
        let id = "three";
        keyring.remove(&key_type, id).await.expect("ES256k key removed");

        // Check that the keys are removed
        let key_type = KeyType::EdDSA;
        let id = "one";
        assert!(keyring.public_key(&key_type, id).await.is_err());
    }
}
