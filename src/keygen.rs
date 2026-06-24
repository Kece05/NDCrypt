use rand::RngCore;
use zeroize::ZeroizeOnDrop; 

use crate::gka::{fill_ring_element, sample_small, ring_multiply, ring_add, RingElement};

// Public and private key similar to double ellipse method but with polynomials instead
pub struct PublicKey {
    // Two public keys, used for cancelation later
    pub a: RingElement,
    pub b: RingElement,
}

#[derive(ZeroizeOnDrop)]
pub struct PrivateKey {
    pub s_lattice: RingElement,
}

// Generates the Ring-LWE keypair
// a  — public uniform random coefficent polynomial
//      b  = a·s + e (the public key, hard to invert without s)
//
// s  — private small polynomial (the lattice secret)
// e  — small noise polynomial to make it extreme hard to break security
pub fn generate_keypair(rng: &mut impl RngCore) -> (PublicKey, PrivateKey) {
    // a randomly has polynomial coefficents generate between 0...12288
    let a         = fill_ring_element(rng);

    // Getting CDB between -2 and 2 for each coefficent
    let s_lattice = sample_small(rng);
    let e         = sample_small(rng);

    // b = (a * s) + e, used later to decode for seed
    let as_product = ring_multiply(&a, &s_lattice);
    let b          = ring_add(&as_product, &e);

    return (
        PublicKey  { a, b },
        PrivateKey { s_lattice },
    )
}