use zeroize::Zeroizing;

use crate::encrypt::Ciphertext;
use crate::keygen::PrivateKey;
use crate::gka::{ring_multiply, ring_subtract, decode_seed};

pub struct DecapsulationResult {
    pub shared_seed: Zeroizing<[u8; 32]>,  // The recovered root shared secret — passed to ndcrypt to derive S using derive_signal_indices()
}

// Used to strip away the lattice noise and recover the seed buried in c2 from cancelation
pub fn decapsulate_payload(ciphertext: &Ciphertext, sk: &PrivateKey) -> DecapsulationResult {
    // Compute c1 * s (Orginial private key)
    let c1_s = ring_multiply(&ciphertext.c1, &sk.s_lattice);

    // Subtract from c2:
    // c2 - (c1 * s) = encoded_seed + error
    // The A terms cancel out completely leaving only the seed and error term
    let noisy_seed_poly = ring_subtract(&ciphertext.c2, &c1_s);

    // The noise is small enough that decode_seed accurate get seed with the given defined bounds
    let shared_seed = decode_seed(&noisy_seed_poly);

    return DecapsulationResult { shared_seed: Zeroizing::new(shared_seed), };
}