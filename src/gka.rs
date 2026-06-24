use once_cell::sync::Lazy;
use rand::RngCore;
use concrete_ntt::prime64::Plan;
use subtle::{Choice, ConditionallySelectable, ConstantTimeLess};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::params::{N, Q, SIGNAL_COUNT};


static NTT_PLAN: Lazy<Plan> = Lazy::new(|| {
    Plan::try_new(N, Q as u64).expect("NTT plan construction failed for N=1024, Q=12289")
});

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RingElement {
    pub coeffs: [u16; N],
}

// Samples a uniform polynomial over Z_q where each coefficient is 0..12288
pub fn fill_ring_element(rng: &mut impl RngCore) -> RingElement {
    let mut element = RingElement { coeffs: [0u16; N] };

    // Killing off the larger numbers using a bit mask
    const BIT_MASK: u32 = 0x3FFF;
    for i in 0..N {
        loop {
            // Cannot divide by 2 because will cause skewness
            let candidate = rng.next_u32() & BIT_MASK;
            
            // Confirming it is within the bounds
            if candidate < Q.into() {
                element.coeffs[i] = candidate as u16;
                break;
            }
        }
    }

    return element;
}

// Creates the tiny noise that makes the lattice math hard to invert
pub fn sample_small(rng: &mut impl RngCore) -> RingElement {
    let mut element = [0u16; N];
    
    // Only runs 128 times since .next_32u
    for i in 0..(N / 8) {
        let noise = rng.next_u32();

        // Taking 4 bits at a time with a bit mask for the small numbers
        for j in 0..8 {
            let chunk = (noise >> (j * 4)) & 0x0F;
            
            // Can either be 0 or 1, creates the CBD -2, -1, 0, 1, 2
            let a = (chunk & 1) + ((chunk >> 1) & 1);
            let b = ((chunk >> 2) & 1) + ((chunk >> 3) & 1);

            let coeff = (a + Q as u32 - b) % (Q as u32);

            element[i * 8 + j] = coeff as u16;
        }
    }

    return RingElement { coeffs: element };
}

// Adds two ring elements coefficient-wise mod Q
pub fn ring_add(a_co: &RingElement, b_co: &RingElement) -> RingElement {
    let mut new_ring = [0u16; N];

    for i in 0..N {
        new_ring[i] = (a_co.coeffs[i] + b_co.coeffs[i]) % Q;
    }

    return RingElement { coeffs: new_ring };
}

// Subtracts two ring elements coefficient-wise mod Q
pub fn ring_subtract(a_co: &RingElement, b_co: &RingElement) -> RingElement {
    let mut new_ring = [0u16; N];

    for i in 0..N {
        new_ring[i] = (a_co.coeffs[i] + Q - b_co.coeffs[i]) % Q;
    }

    return RingElement { coeffs: new_ring };
}

// Multiplies two polynomials in Z_q[x]/(x^1024 + 1) using NTT
pub fn ring_multiply(a_co: &RingElement, b_co: &RingElement) -> RingElement {
    // Lazy<Plan> is already initialised by the time any thread reaches here.
    let plan = &*NTT_PLAN;

    let mut a_ntt = [0u64; N];
    let mut b_ntt = [0u64; N];

    for i in 0..N {
        a_ntt[i] = a_co.coeffs[i] as u64;
        b_ntt[i] = b_co.coeffs[i] as u64;
    }

    // Creates factored out polynomials that are the zero divisors
    plan.fwd(&mut a_ntt);
    plan.fwd(&mut b_ntt);

    // Multiplying corresponding indexes (a_n * b_n) mod 12289
    let mut result_ntt = [0u64; N];
    for i in 0..N {
        result_ntt[i] = (a_ntt[i] * b_ntt[i]) % (Q as u64);
    }

    plan.inv(&mut result_ntt);

    let mut final_result = [0u16; N];
    for i in 0..N {
        // 12277 = inverse of N (1024) mod Q (12289)
        final_result[i] = ((result_ntt[i] * 12277) % (Q as u64)) as u16;
    }

    return RingElement { coeffs: final_result };
}

// Encodes a 32-byte seed into a polynomial used to send the orginial sender
pub fn encode_seed(seed: &[u8; 32]) -> RingElement {
    let mut coeffs = [0u16; N];

    // Flatten the 32-byte seed into 256 sequential bits (1D array)
    for i in 0..32 {
        for j in 0..8 {
            // // Isolate a single bit using a right shift and a bitmask
            let bit = (seed[i] >> j) & 1;

            // Map the 2D byte/bit index to a flat 1D polynomial index
            coeffs[i * 8 + j] = if bit == 1 { 6144 } else { 0 };
        }
    }

    return RingElement { coeffs };
}

// Decodes a noisy polynomial back into a 32-byte seed 
pub fn decode_seed(element: &RingElement) -> [u8; 32] {
    let mut seed = [0u8; 32];

    // Reverses the process of encoder
    for i in 0..32 {
        for j in 0..8 {
            let coeff = element.coeffs[i * 8 + j];

            // if in range which is Q/4 - 3Q/4 it is one since area potientially covered is by 1
            let low: Choice  = !coeff.ct_lt(&3072_u16);        
            let high: Choice = coeff.ct_lt(&9217_u16);
            let is_one = u8::conditional_select(&0u8, &1u8, low & high);

            seed[i] |= is_one << j;
        }
    }

    return seed;
}

// Derives the 32 signal coordinate indices (S) from the shared seed and a nonce.
pub fn derive_signal_indices(seed: &[u8; 32], nonce: u64) -> [u16; SIGNAL_COUNT] {
    use sha3::{Digest, Sha3_256};
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use rand::seq::SliceRandom;

    // domain tag + nonce + seed -> deterministic 32-byte PRNG seed
    let mut hasher = Sha3_256::new();
    hasher.update([0x01]);               // domain tag
    hasher.update(nonce.to_le_bytes());  // different S per point
    hasher.update(seed);                 // root shared secret
    let digest = hasher.finalize();

    let mut s_seed = [0u8; 32];
    s_seed.copy_from_slice(&digest);

    // Deterministic shuffle same inputs always produce same S, both ends can generate the same S
    let mut prng = StdRng::from_seed(s_seed);
    let mut indices: Vec<u16> = (0..N as u16).collect();
    indices.shuffle(&mut prng);

    // Take the first 32 and sort for fast extraction later
    let mut signal_indices = [0u16; SIGNAL_COUNT];
    signal_indices.copy_from_slice(&indices[..SIGNAL_COUNT]);
    signal_indices.sort_unstable();

    return signal_indices
}