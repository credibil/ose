//! # Signing and Encryption Utilities
//!
//! This crate provides common utilities for the Credibil project and is not
//! intended to be used directly.

mod encryption;
mod key;
mod signing;

use std::fmt::Display;

use serde::{Deserialize, Serialize};

pub use encryption::{AlgAlgorithm, EncAlgorithm, Receiver};
pub use key::{
    ED25519_CODEC, MultiKey, PublicKey, SecretKey, SharedSecret, TAG_PUBKEY_FULL, X25519_CODEC,
};
pub use signing::Signer;

/// Algorithm is used to specify the signing algorithm used by the signer.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Algorithm {
    /// Algorithm for the secp256k1 curve
    #[serde(rename = "ES256K")]
    ES256K,

    /// Algorithm for the Ed25519 curve
    #[default]
    #[serde(rename = "EdDSA")]
    EdDSA,
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Cryptographic key type.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub enum KeyType {
    /// Octet key pair (Edwards curve)
    #[default]
    #[serde(rename = "OKP")]
    Okp,

    /// Elliptic curve key pair
    #[serde(rename = "EC")]
    Ec,

    /// Octet string
    #[serde(rename = "oct")]
    Oct,
}

/// Cryptographic curve type.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub enum Curve {
    /// Ed25519 signature (DSA) key pairs.
    #[default]
    Ed25519,

    /// X25519 function (encryption) key pairs.
    X25519,

    /// secp256k1 curve.
    #[serde(rename = "ES256K", alias = "secp256k1")]
    Es256K,

    /// secp256r1 curve.
    P256,
}
