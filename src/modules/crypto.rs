use snow::Keypair;
use std::fs;

use super::error::KeyGenerationError;

pub const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

pub fn generate_or_load_keypair() -> Result<Keypair, KeyGenerationError> {
    if let Ok(private_key) = fs::read("private.key") {
        if let Ok(public_key) = fs::read("public.key") {
            println!("Existing keypair loaded.");
            return Ok(Keypair {
                public: public_key,
                private: private_key,
            });
        }
    }

    println!("No keypair found, creating a new one...");
    let keypair =
        snow::Builder::new(PATTERN.parse().expect("Invalid snow pattern")).generate_keypair()?;

    fs::write("private.key", &keypair.private)?;
    fs::write("public.key", &keypair.public)?;
    println!("New keypair saved to private.key and public.key.");

    Ok(keypair)
}
