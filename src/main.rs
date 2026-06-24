use rand::thread_rng;

pub mod params;
pub mod gka;
pub mod keygen;
pub mod encrypt;
pub mod decrypt;
pub mod ndcrypt;

fn main() {
    println!("--- NDCrypt: Full Handshake Simulation ---\n");
    let mut rng = thread_rng();

    // Step 1 — Alice generates a Ring-LWE keypair
    // Public key (a, b) goes to Bob
    // Private key (s) stays with Alice forever
    println!("[*] Alice generating keypair...");
    let (public_key, private_key) = keygen::generate_keypair(&mut rng);
    println!("    -> Public key sent to Bob.");
    println!("    -> Private key stays with Alice.");

    // Step 2 — Bob hides a random seed inside the lattice math and sends it
    // Bob ends up with shared_seed
    println!("\n[*] Bob encapsulating seed...");
    let bob_result = encrypt::encapsulate_payload(&public_key, &mut rng);
    println!("    -> Seed hidden inside ciphertext (c1, c2) and sent to Alice.");

    // Step 3 — Alice uses her private key to dig the seed back out of the math
    // Alice ends up with the same shared_seed
    println!("\n[*] Alice decapsulating...");
    let alice_result = decrypt::decapsulate_payload(&bob_result.ciphertext, &private_key);
    println!("    -> Seed recovered from lattice noise.");

    // Step 4 — Verify both sides have the same seed
    // Everything in ndcrypt (S per point, keystream per point) comes from this seed
    println!("\n--- Verification ---\n");
    println!("Bob   shared seed (first 5 bytes): {:?}", &bob_result.shared_seed[..5]);
    println!("Alice shared seed (first 5 bytes): {:?}", &alice_result.shared_seed[..5]);

    // CHANGED: both shared_seed fields are now Zeroizing<[u8; 32]>, so we dereference
    // with * to get the inner [u8; 32] for comparison
    if *bob_result.shared_seed == *alice_result.shared_seed {
        println!("\n[+] SUCCESS — seeds match.");
        println!("[+] Both parties can now derive identical S for any nonce.");
        println!("[+] NDCrypt layer ready.\n");
    } else {
        println!("\n[-] FAILURE — seeds do not match.");
        return;
    }

    // Step 5 — NDCrypt encrypt and decrypt a message using S
    let message = b"Hello from NDCrypt";
    println!("Original message: {:?}\n", std::str::from_utf8(message).unwrap());

    // Encrypt — uses seed + nonce 0 to derive S internally
    // CHANGED: encrypt now returns Result<>, use unwrap_or_else to handle errors cleanly
    let point = ndcrypt::encrypt(message, &bob_result.shared_seed, 0)
        .unwrap_or_else(|e| { println!("[-] Encrypt error: {:?}", e); std::process::exit(1); });
    println!("Encrypted point (first 8 of 1024 coordinates): {:?}", &point.coeffs[..8]);

    // Decrypt — uses same seed + nonce 0 to derive same S internally
    // CHANGED: decrypt now returns Result<>, use unwrap_or_else to handle errors cleanly
    let recovered = ndcrypt::decrypt(&point, &alice_result.shared_seed, 0)
        .unwrap_or_else(|e| { println!("[-] Decrypt error: {:?}", e); std::process::exit(1); });
    println!("\nRecovered message: {:?}", std::str::from_utf8(&recovered).unwrap());

    if message == recovered.as_slice() {
        println!("\n[+] SUCCESS — message encrypted and decrypted correctly.");
    } else {
        println!("\n[-] FAILURE — message does not match.");
    }
}