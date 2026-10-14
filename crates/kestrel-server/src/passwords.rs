//! Argon2id password hashes. Callers must not log the password or the hash.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use std::sync::OnceLock;

pub fn hash_password(password: &str) -> Result<String, crate::ServerError> {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| crate::ServerError::new("password hashing failed"))?;
    Ok(hash.to_string())
}

/// Verify `password` against `hash`. An unreadable hash still runs a verify
/// against a dummy hash so missing users take the same path.
pub fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => {
            if let Ok(parsed) = PasswordHash::new(dummy_hash()) {
                let _ = Argon2::default().verify_password(password.as_bytes(), &parsed);
            }
            false
        }
    }
}

fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash_password("kestrel-dummy-password").unwrap_or_else(|_| String::new()))
}

pub fn random_token(prefix: &str) -> Result<String, crate::ServerError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|err| crate::ServerError::new(format!("random token failed: {err}")))?;
    Ok(format!(
        "{prefix}{}",
        data_encoding::BASE64URL_NOPAD.encode(&bytes)
    ))
}

pub fn token_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    data_encoding::HEXLOWER.encode(Sha256::digest(token.as_bytes()).as_slice())
}

pub fn hashes_equal(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in left.iter().zip(right) {
        diff |= left ^ right;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_use_argon2id_and_reject_the_wrong_secret() {
        let hash = hash_password("correct-horse").unwrap();
        assert!(hash.starts_with("$argon2id$"), "{hash}");
        assert!(verify_password("correct-horse", &hash));
        assert!(!verify_password("wrong-horse", &hash));
        assert!(!verify_password("correct-horse", "not-a-hash"));
        let token = random_token("kst_").unwrap();
        assert!(token.starts_with("kst_"));
        assert!(hashes_equal(&token_hash(&token), &token_hash(&token)));
        assert!(!hashes_equal(&token_hash(&token), &token_hash("kst_other")));
    }
}
