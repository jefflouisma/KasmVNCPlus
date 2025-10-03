use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{Rng, thread_rng};

/// PKCE (Proof Key for Code Exchange) implementation
#[derive(Clone)]
pub struct PkceChallenge {
    pub verifier: String,
    pub challenge: String,
    pub method: String,
}

impl PkceChallenge {
    /// Generate a new PKCE challenge
    pub fn new() -> Self {
        Self::with_method("S256")
    }

    /// Generate PKCE challenge with specific method
    pub fn with_method(method: &str) -> Self {
        let verifier = Self::generate_verifier();
        let challenge = match method {
            "S256" => Self::generate_s256_challenge(&verifier),
            "plain" => verifier.clone(),
            _ => panic!("Unsupported PKCE method: {}", method),
        };

        PkceChallenge {
            verifier,
            challenge,
            method: method.to_string(),
        }
    }

    /// Generate a cryptographically random code verifier
    fn generate_verifier() -> String {
        let mut rng = thread_rng();
        let random_bytes: Vec<u8> = (0..64)
            .map(|_| rng.gen::<u8>())
            .collect();

        URL_SAFE_NO_PAD.encode(&random_bytes)
    }

    /// Generate S256 challenge from verifier
    fn generate_s256_challenge(verifier: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let hash = hasher.finalize();

        URL_SAFE_NO_PAD.encode(&hash)
    }
}

/// Generate a random state parameter for CSRF protection
pub fn generate_state() -> String {
    let mut rng = thread_rng();
    let random_bytes: Vec<u8> = (0..32)
        .map(|_| rng.gen::<u8>())
        .collect();

    URL_SAFE_NO_PAD.encode(&random_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_generation() {
        let pkce = PkceChallenge::new();

        // Verifier should be at least 43 characters (base64url encoded)
        assert!(pkce.verifier.len() >= 43);

        // Challenge should be different from verifier (for S256)
        assert_ne!(pkce.verifier, pkce.challenge);

        // Method should be S256 by default
        assert_eq!(pkce.method, "S256");
    }

    #[test]
    fn test_pkce_plain() {
        let pkce = PkceChallenge::with_method("plain");

        // For plain method, challenge equals verifier
        assert_eq!(pkce.verifier, pkce.challenge);
    }

    #[test]
    fn test_state_generation() {
        let state1 = generate_state();
        let state2 = generate_state();

        // States should be unique
        assert_ne!(state1, state2);

        // State should have reasonable length
        assert!(state1.len() >= 32);
    }
}