use rand::RngCore;
use zeroize::Zeroizing;

use crate::gka::{sample_small, ring_multiply, ring_add, encode_seed, RingElement};
use crate::keygen::PublicKey;

// The two polynomials sent over the network to the other party
pub struct Ciphertext {
    pub c1: RingElement,
    pub c2: RingElement,
}

pub struct EncapsulationResult {
    pub ciphertext:  Ciphertext,
    pub shared_seed: Zeroizing<[u8; 32]>,  // The root shared secret — passed to ndcrypt to derive S using derive_signal_indices()
}

// This encapsulates the seed with in the c2 hide the seed inside the lattice math and send it
pub fn encapsulate_payload(pk: &PublicKey, rng: &mut impl RngCore) -> EncapsulationResult {
    // Generate a random 32-byte seed 
    let mut shared_seed = [0u8; 32];
    rng.fill_bytes(&mut shared_seed);

    // Encode the seed into a polynomial so we can hide it in the math
    let encoded_seed_poly = encode_seed(&shared_seed);

    let s_prime       = sample_small(rng);
    let e_prime       = sample_small(rng);
    let e_prime_prime = sample_small(rng);

    // c1 = (A * s') + e'
    let as_prime = ring_multiply(&pk.a, &s_prime);
    let c1       = ring_add(&as_prime, &e_prime);

    // c2 = (B * s') + e'' + encoded_seed
    // The seed is buried inside c2 under two layers of noise
    let bs_prime = ring_multiply(&pk.b, &s_prime);
    let noisy_c2 = ring_add(&bs_prime, &e_prime_prime);
    let c2       = ring_add(&noisy_c2, &encoded_seed_poly);

    return EncapsulationResult {
        ciphertext: Ciphertext { c1, c2 },
        shared_seed: Zeroizing::new(shared_seed),
    }
}