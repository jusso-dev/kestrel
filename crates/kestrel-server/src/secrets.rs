//! Encrypt notification secrets at rest with age. The identity lives in
//! `data_dir/secret.key` and is not logged.

use age::secrecy::ExposeSecret;
use age::x25519;
use std::io::Write;
use std::path::Path;

pub struct SecretBox {
    identity: x25519::Identity,
}

impl SecretBox {
    pub fn load_or_create(path: &Path) -> Result<Self, crate::ServerError> {
        if path.is_file() {
            crate::perms::restrict_private_key(path)?;
            let text = std::fs::read_to_string(path)?;
            let identity = text
                .trim()
                .parse::<x25519::Identity>()
                .map_err(|err| crate::ServerError::new(format!("secret key: {err}")))?;
            return Ok(Self { identity });
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let identity = x25519::Identity::generate();
        let pem = identity.to_string();
        crate::perms::write_private_key(path, pem.expose_secret())?;
        Ok(Self { identity })
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String, crate::ServerError> {
        let recipient = self.identity.to_public();
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .map_err(|_| crate::ServerError::new("secret encryption failed"))?;
        let mut output = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut output)
            .map_err(|err| crate::ServerError::new(format!("secret encryption failed: {err}")))?;
        writer
            .write_all(plaintext.as_bytes())
            .map_err(|err| crate::ServerError::new(format!("secret encryption failed: {err}")))?;
        writer
            .finish()
            .map_err(|err| crate::ServerError::new(format!("secret encryption failed: {err}")))?;
        Ok(data_encoding::BASE64.encode(&output))
    }

    pub fn decrypt(&self, ciphertext: &str) -> Result<String, crate::ServerError> {
        let bytes = data_encoding::BASE64
            .decode(ciphertext.as_bytes())
            .map_err(|err| crate::ServerError::new(format!("secret decryption failed: {err}")))?;
        let decryptor = age::Decryptor::new(&bytes[..])
            .map_err(|err| crate::ServerError::new(format!("secret decryption failed: {err}")))?;
        let mut reader = decryptor
            .decrypt(std::iter::once(&self.identity as &dyn age::Identity))
            .map_err(|_| crate::ServerError::new("secret decryption failed"))?;
        let mut plaintext = String::new();
        std::io::Read::read_to_string(&mut reader, &mut plaintext)
            .map_err(|_| crate::ServerError::new("secret decryption failed"))?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_round_trip_without_writing_the_plaintext_to_the_key_file() {
        let dir = std::env::temp_dir().join(format!("kestrel-secret-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret.key");
        let box_ = SecretBox::load_or_create(&path).unwrap();
        let stored = box_.encrypt("https://hooks.example/secret").unwrap();
        assert!(!stored.contains("hooks.example"));
        assert!(!std::fs::read_to_string(&path)
            .unwrap()
            .contains("hooks.example"));
        assert_eq!(
            box_.decrypt(&stored).unwrap(),
            "https://hooks.example/secret"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
