use snow::Keypair;
use std::fs;

use super::error::KeyGenerationError;

pub const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

use std::path::Path;

pub fn generate_or_load_keypair(dir: &Path) -> Result<Keypair, KeyGenerationError> {
    let private_key_path = dir.join("private.key");
    let public_key_path = dir.join("public.key");

    if let Ok(private_key) = fs::read(&private_key_path)
        && let Ok(public_key) = fs::read(&public_key_path)
    {
        println!("Existing keypair loaded.");
        return Ok(Keypair {
            public: public_key,
            private: private_key,
        });
    }

    println!("No keypair found, creating a new one...");
    let keypair =
        snow::Builder::new(PATTERN.parse().expect("Invalid snow pattern")).generate_keypair()?;

    fs::write(&private_key_path, &keypair.private)?;
    fs::write(&public_key_path, &keypair.public)?;
    println!("New keypair saved to private.key and public.key.");

    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn makes_new_key() {
        let dir = tempdir().unwrap();
        let keypair = generate_or_load_keypair(dir.path()).unwrap();

        assert!(dir.path().join("private.key").exists());
        assert!(dir.path().join("public.key").exists());
        assert!(!keypair.private.is_empty());
        assert!(!keypair.public.is_empty());
    }

    #[test]
    fn loads_existing_key() {
        let dir = tempdir().unwrap();
        let keypair1 = generate_or_load_keypair(dir.path()).unwrap();
        let keypair2 = generate_or_load_keypair(dir.path()).unwrap();

        assert_eq!(keypair1.public, keypair2.public);
        assert_eq!(keypair1.private, keypair2.private);
    }
}
