use wasm_bindgen::prelude::*;
use rand::thread_rng;
use zeroize::Zeroizing;

// Expose all your existing files
pub mod params;
pub mod gka;
pub mod keygen;
pub mod encrypt;
pub mod decrypt;
pub mod ndcrypt;

#[wasm_bindgen]
pub struct NDCryptWasm {
    pk: Option<keygen::PublicKey>,
    sk: Option<keygen::PrivateKey>,
    shared_seed: Option<Zeroizing<[u8; 32]>>,
}

#[wasm_bindgen]
impl NDCryptWasm {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        NDCryptWasm {
            pk: None,
            sk: None,
            shared_seed: None,
        }
    }

    // User 1 calls this to generate keys. Returns A and B flattened into a 2048-element array
    pub fn generate_keys(&mut self) -> Vec<u16> {
        let mut rng = thread_rng();
        let (pk, sk) = keygen::generate_keypair(&mut rng);
        
        let mut result = Vec::with_capacity(2048);
        result.extend_from_slice(&pk.a.coeffs);
        result.extend_from_slice(&pk.b.coeffs);
        
        self.pk = Some(pk);
        self.sk = Some(sk);
        return result;
    }

    // User 2 receives User 1's key, encapsulates a seed, returns C1 and C2 flattened into 2048 elements
    pub fn encapsulate_seed(&mut self, pubkey_flat: &[u16]) -> Vec<u16> {
        if self.shared_seed.is_some() {
            return vec![];
        }
        if pubkey_flat.len() != 2048 {
            return vec![];
        }

        let mut a_coeffs = [0u16; 1024];
        let mut b_coeffs = [0u16; 1024];
        a_coeffs.copy_from_slice(&pubkey_flat[0..1024]);
        b_coeffs.copy_from_slice(&pubkey_flat[1024..2048]);
        
        let pk = keygen::PublicKey {
            a: gka::RingElement { coeffs: a_coeffs },
            b: gka::RingElement { coeffs: b_coeffs },
        };
        
        let mut rng = thread_rng();
        let enc_result = encrypt::encapsulate_payload(&pk, &mut rng);
        
        self.shared_seed = Some(Zeroizing::new(*enc_result.shared_seed));
        
        let mut result = Vec::with_capacity(2048);
        result.extend_from_slice(&enc_result.ciphertext.c1.coeffs);
        result.extend_from_slice(&enc_result.ciphertext.c2.coeffs);
        return result;
    }

    // User 1 receives user 2's ciphertext and decapsulates to recover the seed
    pub fn decapsulate_seed(&mut self, cipher_flat: &[u16]) -> bool {
        if self.shared_seed.is_some() {
            return false;
        }
        if cipher_flat.len() != 2048 {
            return false;
        }
 
        if let Some(sk) = &self.sk {
            let mut c1_coeffs = [0u16; 1024];
            let mut c2_coeffs = [0u16; 1024];
            c1_coeffs.copy_from_slice(&cipher_flat[0..1024]);
            c2_coeffs.copy_from_slice(&cipher_flat[1024..2048]);
 
            let ciphertext = encrypt::Ciphertext {
                c1: gka::RingElement { coeffs: c1_coeffs },
                c2: gka::RingElement { coeffs: c2_coeffs },
            };
 
            let dec_result = decrypt::decapsulate_payload(&ciphertext, sk);
            self.shared_seed = Some(Zeroizing::new(*dec_result.shared_seed));
            return true;
        }
        return false;
    }

    // Derive a deterministic starting nonce from the shared seed
    pub fn get_nonce_base(&self, party_index: u8) -> u32 {
        use sha3::{Digest, Sha3_256};

        if let Some(seed) = &self.shared_seed {
            let mut hasher = Sha3_256::new();
            hasher.update([0x05]);
            hasher.update([party_index]);
            hasher.update(seed.as_ref());
            let digest = hasher.finalize();
            return u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
        } else {
            return 0;
        }
    }
    // Encrypt raw bytes. Caller builds the full framed payload before passing it in
    pub fn encrypt_bytes(&self, payload: &[u8], nonce: u32) -> Vec<u16> {
        if let Some(seed) = &self.shared_seed {
            if let Ok(point) = ndcrypt::encrypt(payload, &**seed, nonce as u64) {
                return point.coeffs.to_vec();
            }
        }
        return vec![];
    }
 
    // Decrypt a 1024-u16 ciphertext back to raw bytes
    pub fn decrypt_bytes(&self, cipher: &[u16], nonce: u32) -> Vec<u8> {
        if cipher.len() != 1024 {
            return vec![];
        }
        if let Some(seed) = &self.shared_seed {
            let mut coeffs = [0u16; 1024];
            coeffs.copy_from_slice(cipher);
            let point = gka::RingElement { coeffs };
            if let Ok(bytes) = ndcrypt::decrypt(&point, &**seed, nonce as u64) {
                return bytes;
            }
        }
        vec![]
    }

    // Backwards-compatible wrappers
    pub fn encrypt_msg(&self, msg: &str, nonce: u32) -> Vec<u16> {
        return self.encrypt_bytes(msg.as_bytes(), nonce)
    }
 
    pub fn decrypt_msg(&self, cipher: &[u16], nonce: u32) -> String {
        let bytes = self.decrypt_bytes(cipher, nonce);
        return String::from_utf8(bytes).unwrap_or_else(|_| String::new())
    }
}