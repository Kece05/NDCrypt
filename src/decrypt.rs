use zeroize::Zeroizing;

use crate::encrypt::{Ciphertext, hash_public_key, hash_ciphertext, encapsulate_deterministic};
use crate::keygen::{PrivateKey, PublicKey};
use crate::gka::{ring_multiply, ring_subtract, decode_seed};

pub struct DecapsulationResult {
    // The recovered root shared secret.
    // Only present when the re-encryption check passes (FO transform).
    pub shared_seed: Zeroizing<[u8; 32]>,
}

#[derive(Debug)]
pub enum DecapsulationError {
    // The received ciphertext did not pass the FO re-encryption check.
    // This means it was not produced by honest encapsulation: either the
    // ciphertext was forged, malformed, or corrupted in transit.
    InvalidCiphertext,
}

// Decapsulates the seed from a ciphertext using the private key.
//
// FO re-encryption check (fixes the chosen-seed forgery / Bug #1):
//   After recovering the seed candidate m' from the raw Ring-LWE decryption,
//   we re-run encapsulate_deterministic(pk, m', pk_hash) and compare the
//   resulting (c1', c2') against the received (c1, c2) using a constant-time
//   equality check.  If they differ, the ciphertext was not honestly produced
//   and we return InvalidCiphertext instead of leaking m'.
//
// This means setting c1=0, c2=encode_seed(K) no longer works:
//   - The attacker's (0, encode_seed(K)) decrypts to K.
//   - Re-encrypt(K, pk) produces (A·s'+e', B·s'+e''+encode_seed(K)) ≠ (0, encode_seed(K)).
//   - Check fails → abort.  The attacker learns nothing.
pub fn decapsulate_payload(
    ciphertext: &Ciphertext,
    sk: &PrivateKey,
    pk: &PublicKey,
) -> Result<DecapsulationResult, DecapsulationError> {
    // --- Step 1: raw Ring-LWE decryption ---
    let c1_s = ring_multiply(&ciphertext.c1, &sk.s_lattice);
    let noisy_seed_poly = ring_subtract(&ciphertext.c2, &c1_s);
    let seed_candidate = decode_seed(&noisy_seed_poly);

    // --- Step 2: FO re-encryption check ---
    let pk_hash = hash_public_key(pk);
    let reencrypted = encapsulate_deterministic(pk, &seed_candidate, &pk_hash);

    // Constant-time comparison of both polynomial coefficient arrays.
    // We must NOT short-circuit on the first mismatch to avoid timing oracles.
    let ct_hash_received   = hash_ciphertext(ciphertext);
    let ct_hash_reencrypted = hash_ciphertext(&reencrypted);

    let mut mismatch: u8 = 0;
    for (a, b) in ct_hash_received.iter().zip(ct_hash_reencrypted.iter()) {
        mismatch |= a ^ b;
    }

    if mismatch != 0 {
        return Err(DecapsulationError::InvalidCiphertext);
    }

    Ok(DecapsulationResult {
        shared_seed: Zeroizing::new(seed_candidate),
    })
}