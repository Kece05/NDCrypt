use sha3::{Digest, Sha3_256};

use crate::params::{N, Q, SIGNAL_COUNT};
use crate::gka::{derive_signal_indices, RingElement};

#[derive(Debug)]
pub enum NdCryptError {
    MessageTooLong,   // encrypt(): message.len() >= SIGNAL_COUNT
    CorruptedLength,  // decrypt(): recovered length field >= SIGNAL_COUNT
}

// Encrypts a message into a 1024-dimensional point using S
pub fn encrypt(message: &[u8], seed: &[u8; 32], nonce: u64) -> Result<RingElement, NdCryptError> {
    if message.len() >= SIGNAL_COUNT {
        return Err(NdCryptError::MessageTooLong);
    }

    let signal_indices = derive_signal_indices(seed, nonce);

    // Fill background with uniform Z_Q values using rejection sampling
    let background = derive_background_zq(seed, nonce, N);
    let mut point = RingElement { coeffs: [0u16; N] };
    for i in 0..N {
        point.coeffs[i] = background[i];
    }

    // Hide the length in the very first signal coordinate S[0]
    let mask_len = derive_zq_mask(seed, nonce, 0);
    point.coeffs[signal_indices[0] as usize] = (message.len() as u16 + mask_len) % Q;

    // Hide the actual message in the remaining coordinates S[1..]
    for i in 0..message.len() {
        let mask = derive_zq_mask(seed, nonce, (i + 1) as u64);
        point.coeffs[signal_indices[i + 1] as usize] = (message[i] as u16 + mask) % Q;
    }

    return Ok(point);
}

// Decrypts a 1024-dimensional point back into message bytes
pub fn decrypt(point: &RingElement, seed: &[u8; 32], nonce: u64) -> Result<Vec<u8>, NdCryptError> {
    // Reconstructing S
    let signal_indices = derive_signal_indices(seed, nonce);

    // Retreving the message length, subtract the same Z_Q mask we added during encrypt
    let mask_len = derive_zq_mask(seed, nonce, 0);
    let enc_len_val = point.coeffs[signal_indices[0] as usize];
    let message_len = ((enc_len_val + Q - mask_len) % Q) as usize;

    if message_len >= SIGNAL_COUNT {
        return Err(NdCryptError::CorruptedLength);
    }

    // Extracting exactly that many bytes from S[1..], reversing the additive mask
    let mut message = Vec::with_capacity(message_len);
    for i in 0..message_len {
        let mask = derive_zq_mask(seed, nonce, (i + 1) as u64);
        let enc_val = point.coeffs[signal_indices[i + 1] as usize];
        // Subtract mask mod Q, then take low 8 bits to recover the original byte
        let plain_byte = ((enc_val + Q - mask) % Q) as u8;
        message.push(plain_byte);
    }

    return Ok(message);
}

// Produces 'count' uniform Z_Q values using counter-mode SHA3 with rejection sampling
fn derive_background_zq(seed: &[u8; 32], nonce: u64, count: usize) -> Vec<u16> {
    let mut result = Vec::with_capacity(count);
    let mut counter: u64 = 0;

    while result.len() < count {
        let mut hasher = Sha3_256::new();
        hasher.update([0x03]);
        hasher.update(nonce.to_le_bytes());
        hasher.update(counter.to_le_bytes());
        hasher.update(seed);
        let block = hasher.finalize();
        counter += 1;

        // Read the 32-byte block as 16 little-endian u16 values
        for j in 0..16 {
            let raw = u16::from_le_bytes([block[j * 2], block[j * 2 + 1]]);
            // 14-bit mask same technique as fill_ring_element in gka
            let candidate = raw & 0x3FFF;
            if candidate < Q {
                result.push(candidate);
                if result.len() == count {
                    break;
                }
            }
        }
    }

    return result;
}

// Derives a single uniform Z_Q mask value for one signal slot
fn derive_zq_mask(seed: &[u8; 32], nonce: u64, slot_index: u64) -> u16 {
    let mut hasher = Sha3_256::new();
    hasher.update([0x04]);
    hasher.update(nonce.to_le_bytes());
    hasher.update(slot_index.to_le_bytes());
    hasher.update(seed);
    let digest = hasher.finalize();

    // 14-bit mask then reject-if->= Q, same as derive_background_zq.
    // Loop until we get a value in [0, Q) — almost always one iteration.
    let mut i = 0;
    loop {
        let raw = u16::from_le_bytes([digest[i % 32], digest[(i + 1) % 32]]);
        let candidate = raw & 0x3FFF;
        if candidate < Q {
            return candidate;
        }
        i += 2;
    }
}