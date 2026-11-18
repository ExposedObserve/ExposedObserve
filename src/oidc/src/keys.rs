// Copyright (C) 2026 Mike Sauh
//
// This file is part of ExposedObserve, a modified fork of OpenObserve.
// OpenObserve is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// Original project: https://github.com/openobserve/openobserve
//
// This file was created independently to add OIDC authentication and claim-based authorization.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! The secret that protects the OIDC cookies.
//!
//! The self-contained token cookie carries the access, refresh and id tokens,
//! so it has to be encrypted rather than merely signed. The key is shared by
//! every node of a cluster: when `OIDC_SESSION_KEY` is not set, one random
//! key is generated and stored in the shared meta DB.

use std::sync::Arc;

use base64::Engine as _;
use cookie::Key;
use tokio::sync::OnceCell;

use crate::errors::AuthError;

/// `cookie` needs 64 bytes: 32 for the signing key and 32 for the encryption key.
pub const SESSION_KEY_LEN: usize = 64;

/// The shortest key an operator may configure.
///
/// A shorter key is stretched to [`SESSION_KEY_LEN`] rather than rejected, so
/// an existing 32-byte secret keeps working instead of failing the start-up.
pub const SESSION_KEY_MIN_LEN: usize = 32;

static SESSION_KEY: OnceCell<Arc<Key>> = OnceCell::const_new();

/// The process-wide session key.
///
/// `OIDC_SESSION_KEY` wins when it is set; otherwise the key comes from the
/// shared meta DB, so every node of a cluster seals and opens the same
/// cookies.
pub async fn session_key() -> Result<Arc<Key>, AuthError> {
    if let Some(key) = SESSION_KEY.get() {
        return Ok(key.clone());
    }
    if let Some(key) = TEST_KEY.with(|slot| slot.borrow().clone()) {
        return Ok(key);
    }
    let key = Arc::new(resolve_session_key().await?);
    let _ = SESSION_KEY.set(key.clone());
    Ok(SESSION_KEY.get().cloned().unwrap_or(key))
}

thread_local! {
    /// A key installed by a test, so the cookie tests do not need the meta DB.
    static TEST_KEY: std::cell::RefCell<Option<Arc<Key>>> = const { std::cell::RefCell::new(None) };
}

/// Install a key for the current thread. Intended for tests only.
#[doc(hidden)]
pub fn set_session_key_for_tests(key: Key) {
    TEST_KEY.with(|slot| *slot.borrow_mut() = Some(Arc::new(key)));
}

/// The raw 64 key bytes, as stored in the meta DB or decoded from the env.
async fn resolve_session_key() -> Result<Key, AuthError> {
    if let Some(key) = session_key_from_env()? {
        return Ok(key);
    }
    let stored = db::metas::oidc_session_key::get()
        .await
        .map_err(|e| AuthError::internal("reading the OIDC session key", e))?;
    if let Some(stored) = stored
        && let Ok(key) = decode_key(&stored)
    {
        return Ok(key);
    }
    let candidate = base64::engine::general_purpose::STANDARD.encode(random_key_bytes());
    let stored = db::metas::oidc_session_key::get_or_create(&candidate)
        .await
        .map_err(|e| AuthError::internal("storing the OIDC session key", e))?;
    decode_key(&stored)
}

/// The key configured through `OIDC_SESSION_KEY`, if the operator set one.
fn session_key_from_env() -> Result<Option<Key>, AuthError> {
    let Ok(raw) = std::env::var(crate::config::OIDC_SESSION_KEY) else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|e| AuthError::config(format!("OIDC_SESSION_KEY is not valid base64: {e}")))?;
    stretch_key(&decoded)
        .map(Some)
        .map_err(|e| AuthError::config(format!("OIDC_SESSION_KEY is not usable: {e}")))
}

/// Decode a stored key, which is base64-encoded like the env value.
fn decode_key(stored: &str) -> Result<Key, AuthError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(stored.trim())
        .map_err(|e| AuthError::internal("decoding the stored OIDC session key", e))?;
    stretch_key(&decoded)
        .map_err(|e| AuthError::internal_msg(format!("the stored OIDC session key: {e}")))
}

/// Turn the configured secret into the 64 bytes `cookie` needs.
///
/// A secret of exactly [`SESSION_KEY_LEN`] bytes is used as is. A shorter one is
/// stretched, so an existing 32-byte secret keeps working instead of failing
/// the start-up. Anything shorter than [`SESSION_KEY_MIN_LEN`] is refused: there
/// is not enough entropy to protect the tokens.
fn stretch_key(secret: &[u8]) -> Result<Key, String> {
    if secret.len() == SESSION_KEY_LEN {
        return Key::try_from(secret).map_err(|e| e.to_string());
    }
    if secret.len() < SESSION_KEY_MIN_LEN {
        return Err(format!(
            "the key must be at least {SESSION_KEY_MIN_LEN} bytes, got {}",
            secret.len()
        ));
    }
    let mut stretched = [0u8; SESSION_KEY_LEN];
    for (block, chunk) in stretched.chunks_mut(32).enumerate() {
        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut hasher, secret);
        sha2::Digest::update(&mut hasher, [block as u8]);
        chunk.copy_from_slice(&sha2::Digest::finalize(hasher));
    }
    Key::try_from(stretched.as_slice()).map_err(|e| e.to_string())
}

/// Cryptographically random key material.
fn random_key_bytes() -> Vec<u8> {
    config::utils::rand::random_bytes(SESSION_KEY_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_key_rejects_a_short_key() {
        let encoded = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(decode_key(&encoded).is_err());
    }

    #[test]
    fn decode_key_accepts_a_64_byte_key() {
        let encoded = base64::engine::general_purpose::STANDARD.encode([7u8; SESSION_KEY_LEN]);
        assert!(decode_key(&encoded).is_ok());
    }

    #[test]
    fn a_32_byte_key_is_stretched_instead_of_refused() {
        // An existing 32-byte secret has to keep working, so it is stretched
        // rather than rejected.
        let encoded = base64::engine::general_purpose::STANDARD.encode([3u8; SESSION_KEY_MIN_LEN]);
        assert!(decode_key(&encoded).is_ok());
    }

    #[test]
    fn stretching_is_deterministic() {
        let secret = [9u8; SESSION_KEY_MIN_LEN];
        let first = stretch_key(&secret).expect("a 32-byte key must stretch");
        let second = stretch_key(&secret).expect("a 32-byte key must stretch");
        assert_eq!(first, second);
    }

    #[test]
    fn different_secrets_stretch_to_different_keys() {
        let first = stretch_key(&[1u8; SESSION_KEY_MIN_LEN]).expect("stretch must work");
        let second = stretch_key(&[2u8; SESSION_KEY_MIN_LEN]).expect("stretch must work");
        assert_ne!(first, second);
    }

    #[test]
    fn random_key_bytes_are_full_length() {
        assert_eq!(random_key_bytes().len(), SESSION_KEY_LEN);
    }
}
