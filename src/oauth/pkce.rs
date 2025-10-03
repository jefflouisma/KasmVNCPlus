use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use rand::{RngCore, thread_rng};
use sha2::{Digest, Sha256};

// Generates a new, random code verifier.
pub fn generate_code_verifier() -> String {
    let mut verifier = [0u8; 32];
    thread_rng().fill_bytes(&mut verifier);
    BASE64_URL_SAFE_NO_PAD.encode(verifier)
}

// Hashes the code verifier to create a code challenge.
pub fn generate_code_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = hasher.finalize();
    BASE64_URL_SAFE_NO_PAD.encode(challenge)
}

// Generates a random state string for CSRF protection.
pub fn generate_state() -> String {
    let mut state = [0u8; 16];
    thread_rng().fill_bytes(&mut state);
    BASE64_URL_SAFE_NO_PAD.encode(state)
}
