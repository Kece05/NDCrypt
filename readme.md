# NDCrypt

**NDCrypt** is a post-quantum end-to-end encrypted chat system built in Rust and compiled to WebAssembly. It pairs a **Ring Learning With Errors (Ring-LWE) Key Encapsulation Mechanism** with a deterministic coordinate-hiding symmetric cipher, running entirely in the browser. The relay server never sees plaintext — it only forwards opaque encrypted arrays.

---

## Architecture Overview

```
Browser A                      Python Relay Server               Browser B
─────────                      ───────────────────               ─────────
NDCryptWasm (Rust/WASM)        server.py                         NDCryptWasm (Rust/WASM)
     │                              │                                  │
     │── pubkey ───────────────────►│── pubkey + session_id ──────────►│
     │                              │                                  │
     │◄── ciphertext + confirm ─────│◄─ ciphertext + confirm ──────────│
     │                              │                                  │
     │── confirm_ack ──────────────►│── confirm_ack ──────────────────►│
     │                              │                                  │
     │◄══ E2EE tunnel established ══════════════════════════════════════│
     │                              │                                  │
     │── { nonce, array[1024] } ───►│── { nonce, array[1024] } ───────►│
     │    encrypted NDCrypt point   │    server sees only this          │    decrypt with same seed
```

The server sees public keys, opaque ciphertext arrays, and nonces. It never has the shared seed, never has S, and cannot decrypt any message.

---

## Mathematical Parameters

All Phase 1 lattice operations occur within the polynomial quotient ring:

R_q = Z_q[X]/(X^N + 1)

| Parameter | Value | Reason |
|---|---|---|
| N | 1024 | Dimension — determines search space C(1024,32) ≈ 2^210 |
| q | 12289 | Prime equal to 3 × 2^12 + 1 — NTT-friendly field |
| SIGNAL_COUNT | 32 | Signal coordinates per point — 31 bytes payload capacity |
| Encoding scalar | 6144 = floor(q/2) | Maximally separated from 0 on the modular clock |
| Noise distribution χ | Centered Binomial | Coefficients in {-2, -1, 0, 1, 2} |

---

## Phase 1 — Ring-LWE Key Encapsulation

### Key Generation (keygen.rs)

Alice generates a uniform polynomial a from R_q, samples a secret s from χ and error e from χ, and computes her public key:

    b = a · s + e  (mod q)

- Public key: (a, b) — sent to Bob over the open relay
- Private key: s — never leaves Alice's browser

### Encapsulation (encrypt.rs)

Bob generates a random 32-byte root seed and encodes it bit-by-bit into a message polynomial m where bit 0 maps to coefficient 0 and bit 1 maps to coefficient 6144. He samples ephemeral noise s', e', e'' from χ and produces:

    c1 = a · s' + e'         (mod q)
    c2 = b · s' + e'' + m    (mod q)

Bob sends (c1, c2) to Alice. His ephemeral secrets s', e', e'' are immediately discarded — they never appear in any output.

### Decapsulation (decrypt.rs)

Alice computes:

    c2 - c1 · s = m + (e · s' + e'' - e' · s)   (mod q)

The a · s · s' terms cancel exactly. The residual noise is small so it never pushes any coefficient across the decoding thresholds. Alice reads each recovered coefficient: values in (q/4, 3q/4) = (3072, 9216) decode as 1, everything else as 0. The 32-byte seed is recovered exactly.

### Polynomial Multiplication (gka.rs)

Ring multiplication uses a pure Rust negacyclic Number Theoretic Transform (NTT) over

    Rq = Zq[X]/(X^1024 + 1)

Each multiplication performs:

1. Multiply coefficients by precomputed powers of ψ (pre-twist)
2. Forward radix-2 Cooley-Tukey NTT
3. Pointwise multiplication in the transform domain
4. Inverse NTT
5. Multiply by N⁻¹ and ψ⁻ⁱ (post-twist)

The implementation uses precomputed twiddle factors and roots of unity for q = 12289 and performs polynomial multiplication in O(N log N) time while remaining entirely pure Rust and fully WebAssembly compatible.

---

## Phase 2 — Coordinate Hiding Cipher (ndcrypt.rs)

Once the 32-byte seed is synchronized on both sides, all messages use the coordinate hiding layer. The seed and an incrementing nonce drive every derivation.

### Signal Index Derivation

    s_seed = SHA3-256([0x01] || nonce || seed)
    S = Fisher-Yates shuffle of [0..1023] seeded by s_seed, first 32 indices sorted

Both parties derive the same S for the same nonce. The nonce increments per point so S is never reused across messages.

### Background Generation

    background[i] = SHA3-256([0x03] || nonce || counter || seed) with rejection sampling

Produces 1024 values uniform over Z_q via counter-mode hashing. Rejection sampling (14-bit mask, discard >= q) ensures no bias toward any value.

### Masking and Embedding

For each payload byte p_i:

    point[S[i+1]] = (p_i + mask_i) mod q

where mask_i = SHA3-256([0x04] || nonce || i || seed), reduced to a uniform value in [0, q).

Adding a uniform mask to a value and reducing mod q produces a uniform output. Signal coordinates become statistically identical to background coordinates. An attacker with the ciphertext point cannot distinguish which 32 of the 1024 coordinates carry the message.

The message length is hidden in signal coordinate S[0], also masked: (len + mask_0) % q. Decryption recovers the length first, then exactly that many bytes.

### Domain Separation Tags

| Tag | Purpose |
|---|---|
| 0x01 | Signal index derivation (S) |
| 0x03 | Background noise generation |
| 0x04 | Per-slot masks |
| 0x05 | Nonce base derivation (party-specific starting point) |

No two derivations from the same seed can interfere with each other.

---

## WebAssembly Interface (lib.rs)

The NDCryptWasm class is the browser-facing API, exposed via wasm-bindgen. Each browser tab creates one instance and holds all state (keypair, shared seed) inside it.

```javascript
const engine = new NDCryptWasm();
```

### Handshake Methods

```javascript
// Alice — Step 1: generate keypair, broadcast public key
const pubkeyFlat = engine.generate_keys();
// Returns: Uint16Array(2048) — a.coeffs[1024] + b.coeffs[1024]

// Bob — Step 2: receive Alice's pubkey, encapsulate seed
const cipherFlat = engine.encapsulate_seed(pubkeyFlat);
// Returns: Uint16Array(2048) — c1.coeffs[1024] + c2.coeffs[1024]
// Bob now has shared_seed internally

// Alice — Step 3: receive Bob's ciphertext, recover seed
const ok = engine.decapsulate_seed(cipherFlat);
// Returns: boolean — true if decapsulation succeeded
// Alice now has shared_seed internally, identical to Bob's
```

### Nonce Management

```javascript
// Derive a deterministic starting nonce for this party
// party_index=0 (Alice), party_index=1 (Bob) → disjoint nonce spaces
const nonceBase = engine.get_nonce_base(partyIndex);
let myNonce = nonceBase & 0x7FFFFFFF;  // mask to 31 bits
// Bit 31 is reserved for key confirmation messages only
```

### Encryption and Decryption

```javascript
// Encrypt raw bytes — payload must be <= 31 bytes
const point = engine.encrypt_bytes(payload, nonce);
// Returns: Uint16Array(1024) — the NDCrypt ciphertext point

// Decrypt
const bytes = engine.decrypt_bytes(point, nonce);
// Returns: Uint8Array — recovered payload bytes

// String convenience wrappers (<=31 byte strings only)
const point = engine.encrypt_msg(text, nonce);
const text  = engine.decrypt_msg(point, nonce);
```

---

## Key Confirmation (MITM Prevention)

<<<<<<< Updated upstream
After the handshake, both parties verify the exchange was not intercepted.

```
CONFIRM_TAG         = fixed byte sequence known to both clients
NONCE_CONFIRM_BOB   = 0x80000000  (bit 31 set — reserved nonce space)
NONCE_CONFIRM_ALICE = 0x80000001

Bob encrypts CONFIRM_TAG with NONCE_CONFIRM_BOB and sends it alongside his ciphertext.

Alice decapsulates, derives the same seed, decrypts the confirmation — if it matches CONFIRM_TAG, Bob provably encapsulated against her real public key. A MITM who swapped the public key produces a different seed and cannot produce a matching confirmation. Alice then sends her own confirmation back. Only after both confirmations pass does either side mark the channel secure.
```
=======

## Key Confirmation

After encapsulation, both peers perform a key-confirmation exchange using the
newly established shared seed.

Bob encrypts a fixed confirmation tag under the shared seed and sends it with
his encapsulation ciphertext. Alice decrypts and verifies the tag after
decapsulation, then returns her own confirmation.

This proves both peers derived the same session key before encrypted messaging
begins.

**Important:** this confirms possession of the shared key, but does **not**
authenticate the remote user's identity. Without long-term identity keys,
certificates, or a trust-on-first-use (TOFU) mechanism, an active relay can
still impersonate another participant by initiating its own independent
handshake.
>>>>>>> Stashed changes

---

## Message and File Transfer Protocol

Every transmission is chunked because NDCrypt carries at most 31 bytes per point.

### Wire Format

```json
{
  "type":        "ndcrypt",
  "kind":        "meta or data",
  "transferId":  12345,
  "chunkIndex":  0,
  "totalChunks": 47,
  "totalBytes":  1450,
  "nonce":       98234,
  "array":       [1024 u16 values]
}
```

kind, transferId, chunkIndex, totalChunks, totalBytes are plaintext. Chunk sequencing is not secret — only array carries encrypted content.

### Transfer Flow

Every transfer sends two streams in parallel:

**Meta stream** (kind: "meta") — encodes a small binary header describing the transfer:
- Text message: { k: 't', name: 'Alice' }
- File: { k: 'f', name: 'Alice', filename: 'photo.jpg', mime: 'image/jpeg', size: 148234 }

**Data stream** (kind: "data") — the actual payload chunked into 31-byte pieces, each encrypted independently with a unique nonce.

The receiver buffers chunks by (transferId, kind) in a sparse array keyed by chunkIndex. When all chunks arrive the stream is merged. When both meta and data are complete, the message or file is rendered.

### Capacity

```
Signal[0]     = length byte (masked)
Signal[1..31] = 31 payload bytes per chunk

Text (31 bytes):  1 chunk  →  2 KB on wire
Text (310 bytes): 10 chunks → 20 KB on wire
File (1 MB):      ~34,000 chunks → ~136 MB on wire
```

The expansion ratio (~66×) is the known cost of using NDCrypt directly for bulk data.

---

## Relay Server (server.py)

<<<<<<< Updated upstream
The Python WebSocket relay routes encrypted frames between peers. It enforces protocol structure but never inspects content.
=======
| Tag | Feature | Description |
|------|---------|-------------|
| S1 | Session pairing | Random 128-bit routing identifier used only to associate Bob's response with the correct Alice. It has no cryptographic meaning. |
| S3 | Origin allowlist | Rejects browser WebSocket connections whose Origin does not match the configured server host. |
| S4 | Rate limiting | Per-IP token bucket (200 message burst, 100 messages/sec sustained) sized for chunked file transfers while limiting abusive traffic. |
| S5 | Path traversal protection | Static files are constrained to the pkg/ directory using absolute-path validation. |
| S6 | Typed exception handling | Explicit exception types replace bare exception handlers. |
| S7 | Handshake state machine | Connections progress through IDLE → PUBKEY_SENT → COMPLETE. Invalid transitions terminate the connection. |
>>>>>>> Stashed changes

### Security Features

| Tag | Feature | Description |
|---|---|---|
| S1 | Session pairing | Opaque session_id (random 32 hex chars) routes Bob's reply to the correct Alice. Carries no cryptographic meaning — real integrity is the confirmation round-trip |
| S3 | Origin allowlist | WebSocket upgrades rejected unless Origin matches server's own host. Computed once at startup, not per-connection |
| S4 | Rate limiting | Token bucket per IP: 20 msg/s burst, refills at 5/s. Flood silently dropped |
| S5 | Path traversal | Static files resolved against absolute pkg/ directory, checked with os.path.commonpath() |
| S6 | Typed exceptions | All bare except: replaced with typed handlers |
| S7 | State machine | Per-session IDLE → PUBKEY_SENT → COMPLETE. Out-of-order frames close the connection |

### Handshake State Machine

```
IDLE
  │  receives pubkey
  ▼
PUBKEY_SENT
  │  receives ciphertext (matching session_id)
  ▼
COMPLETE
  │  normal ndcrypt messages flow
```

### Message Validation

- pubkey.array: exactly 2048 elements
- ciphertext.array: exactly 2048 elements, confirm exactly 1024
- ndcrypt.array: exactly 1024 elements
- totalChunks: bounded by MAX_TOTAL_CHUNKS = 5,000,000
- chunkIndex: must be in [0, totalChunks)
- kind: must be "meta" or "data"

### Nonce Space

```
Bits 0-30:  application message nonces
Bit 31:     reserved for key confirmation only
  0x80000000 = Bob's confirmation nonce
  0x80000001 = Alice's confirmation nonce
```

---

## File Structure

```
ndcrypt/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs        — WASM entry point, NDCryptWasm class
    ├── params.rs     — N, Q, SIGNAL_COUNT constants
    ├── gka.rs        — Ring arithmetic, pure Rust negacyclic NTT, S derivation 
    ├── keygen.rs     — Ring-LWE keypair generation
    ├── encrypt.rs    — Seed encapsulation (Bob)
    ├── decrypt.rs    — Seed decapsulation (Alice)
    └── ndcrypt.rs    — Coordinate hiding encrypt/decrypt

server.py             — Python WebSocket relay
pkg/                  — wasm-pack output (generated)
  ├── ndcrypt_bg.wasm
  └── ndcrypt.js
```

---

## Build and Run

### Requirements

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Install Python WebSocket library
pip install websockets
```

### Build WASM

```bash
wasm-pack build --target web
# Outputs pkg/ndcrypt.js and pkg/ndcrypt_bg.wasm
```

### Run

```bash
python server.py
# http://localhost:8080        local
# http://<your-ip>:8080        LAN peers
```

### Cargo.toml

```toml
[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
wasm-bindgen = "0.2"
rand         = { version = "0.8", features = ["getrandom"] }
getrandom    = { version = "0.2", features = ["js"] }
sha3         = "0.10"
subtle       = "2"
zeroize      = "1"
```

---

## Security Properties

### What the relay server learns

- Public keys (a, b) — public by design
- Ciphertexts (c1, c2) — opaque without Alice's private key
- Nonces — public by design
- Encrypted NDCrypt arrays — 1024 uniform-looking values
- Chunk counts and transfer IDs — not secret

The server learns nothing about message content, sender names, or file contents.

### Security layers

```
Layer 1 — Ring-LWE hardness
Breaking the handshake requires solving Ring-LWE in Z12289[x]/(x^1024+1).
Polynomial arithmetic is accelerated using an NTT implementation, but the
underlying Ring-LWE problem and security assumptions are unchanged.

Layer 2 — Coordinate hiding
  Finding S requires searching C(1024,32) ≈ 2^210 subsets
  Quantum Grover reduces this to ≈ 2^105 — still infeasible
  Distribution matching ensures no statistical test distinguishes signal from noise

Layer 3 — Key confirmation
  MITM who swaps the public key cannot produce a matching confirmation tag
  Both sides get positive proof before marking the channel secure
```

### Known Limitations

<<<<<<< Updated upstream
**IND-CPA only.** The Ring-LWE KEM does not include the Fujisaki-Okamoto transform. It provides IND-CPA security — adequate for ephemeral key exchange with forward secrecy, not IND-CCA2. Private keys must not be reused across sessions.

**StdRng.** gka.rs uses Rust's StdRng (ChaCha12) for the Fisher-Yates shuffle. Pinning to ChaCha20Rng via rand_chacha would make the algorithm explicit for production.

**Expansion ratio.** NDCrypt produces 2048 bytes of ciphertext per 31 bytes of plaintext (~66× expansion). For large file transfers this is significant. The protocol is designed for secure messaging.

**Two-party only.** One Alice and one Bob per session. Group chat requires a separate key agreement protocol.
=======
- **Anonymous key exchange.** The current protocol confirms that both peers derived the same shared session key, but it does not authenticate peer identities. Adding long-term signing keys, certificates, or TOFU fingerprints would provide authenticated key exchange.

- **Replay protection.** Application messages currently rely on nonce uniqueness but do not maintain a replay window. Future versions should reject duplicate nonces.

- **IND-CPA KEM.** The Ring-LWE encapsulation does not currently implement the Fujisaki–Okamoto transform, so it provides IND-CPA rather than IND-CCA2 security.

- **Ciphertext expansion.** Each encrypted point carries at most 31 plaintext bytes, resulting in approximately 66× expansion for bulk data. The protocol is intended primarily for secure messaging rather than high-throughput file transport.

- **Two-party sessions.** The protocol currently supports a single sender and receiver. Multi-party communication would require an additional group key agreement protocol.

- **Metadata visibility.** Although message contents remain encrypted, the relay observes packet timing, message frequency, chunk counts, transfer sizes, and connection patterns.
