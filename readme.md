# NDCrypt — Security Audit Fork

> **⚠️ This fork contains a working proof-of-concept demonstrating that NDCrypt's
> encryption can be completely bypassed by a man-in-the-middle attacker.**
>
> The PoC runs against the **original, unmodified** NdCrypt library code and shows:
> forged ciphertext → key confirmation passes → full message decryption + forgery + bidirectional relay.
>
> **Do not use NDCrypt for any real communication.**

---

## Summary of Findings

| # | Severity | Finding |
|---|----------|---------|
| 1 | **Critical** | Chosen-seed ciphertext forgery — attacker controls the shared secret without solving Ring-LWE |
| 2 | **Critical** | "Key confirmation" (MITM prevention) is defeated by finding #1 — Alice's UI says "E2EE Tunnel Established" while the attacker holds the key |
| 3 | **High** | No message authentication (no MAC/AEAD) — ciphertexts are malleable; attacker can forge/modify messages |
| 4 | **High** | No authentication of peer identity — even if the chosen-seed bug were fixed, a MITM can establish separate keys with Alice and Bob |
| 5 | **Medium** | Nonce spaces are not truly disjoint — random 31-bit bases can overlap, causing nonce reuse under the same seed |
| 6 | **Low** | Client-side chunk reassembly is vulnerable to duplicate-chunk DoS |

---

## Finding 1: Chosen-Seed Ciphertext Forgery (Critical)

### The Bug

`src/decrypt.rs` decapsulates as follows:

```rust
let c1_s = ring_multiply(&ciphertext.c1, &sk.s_lattice);
let noisy_seed_poly = ring_subtract(&ciphertext.c2, &c1_s);
let shared_seed = decode_seed(&noisy_seed_poly);
```

There is **no ciphertext validation** — no Fujisaki-Okamoto transform, no re-encryption
check, no binding to the public key. The function accepts any `(c1, c2)` pair and
decodes whatever polynomial `c2 - c1·s` reduces to.

### The Attack

An attacker (Mallory) constructs:

```
c1 = 0                     (all-zero polynomial)
c2 = encode_seed(K_M)      (public encoding of an attacker-chosen 32-byte seed K_M)
```

When Alice decapsulates:

```
c2 - c1·s = encode_seed(K_M) - 0·s = encode_seed(K_M)
decode_seed(encode_seed(K_M)) = K_M   (exact, zero noise)
```

Alice's private key `s` is **completely irrelevant** — `c1 = 0` cancels it out.
No Ring-LWE computation is needed. The attacker chooses the shared secret.

### Verification

The PoC (`examples/mitm_poc.rs`) demonstrates this against the real NdCrypt code:

```
Mallory picks chosen seed: 4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c
MALLORY FORGES CIPHERTEXT (no Ring-LWE needed):
  c1 = all-zero polynomial (cancels Alice's private key s)
  c2 = encode_seed(K_M)    (public encoding of Mallory's seed)

Mallory predicts Alice will recover seed: 4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c
Mallory's chosen seed:                     4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c
-> Prediction correct: YES

Alice decapsulates forged ciphertext -> seed: 4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c
-> Alice got MALLORY'S seed: YES
```

---

## Finding 2: Key Confirmation Defeated (Critical)

### The Claim

The README states:

> "A MITM who swapped the public key produces a different seed and cannot produce a matching confirmation."

### Why It's False

The key confirmation only proves: *"the sender knows the seed that Alice just decoded."*

Because of Finding 1, Mallory can make Alice decode a seed that **Mallory already knows**
(because Mallory chose it). Mallory then encrypts the `CONFIRM_TAG` ("NDCRYPT-OK")
under that seed, and Alice's verification passes perfectly.

The confirmation is a tautology — it checks whether the sender knows the seed,
and the sender chose the seed.

### PoC Output

```
Mallory generates confirmation tag using her known seed K_M:
  [Alice verifies] confirmation decrypt -> "NDCRYPT-OK"  match=YES

[!] KEY CONFIRMATION PASSES: YES
  -> Alice's UI would display: "E2EE Tunnel Established"
  -> Alice believes she has a quantum-resistant secure channel
  -> In reality, Mallory knows the shared secret!
```

Even if the chosen-seed forgery were fixed, this protocol still lacks authentication
of peer identity. Without signatures, pinned keys, fingerprint comparison, or a PAKE,
a MITM can always establish separate keys with Alice and Bob and relay between them.
This is the fundamental unauthenticated key-exchange problem.

---

## Finding 3: No Message Authentication (High)

`src/ndcrypt.rs` encrypts by masking plaintext bytes and placing them in hidden
coordinates:

```rust
point[S[i+1]] = (message[i] + mask_i) mod q
```

Decryption reverses the masking. There is **no MAC, no AEAD tag, no integrity check**
beyond a length-field sanity check (`message_len < 32`).

A random forged point passes the length check with probability 32/12289 ≈ 0.26%.
More importantly, once an attacker knows the seed (via Finding 1), they can freely
decrypt, forge, modify, and replay messages. A secure design would use an AEAD
(AES-GCM, ChaCha20-Poly1305) with metadata bound as associated data.

---

## Finding 4: No Peer Identity Authentication (High)

The handshake has no mechanism to verify that Alice is talking to the real Bob
(and vice versa). There are no:
- Digital signatures over the transcript
- Long-term identity keys
- Pre-shared key / PAKE verification
- Key fingerprint comparison (like Signal's safety numbers)

Even with a perfect KEM, this is vulnerable to classic MITM key-substitution.

---

## Finding 5: Nonce Spaces Are Not Disjoint (Medium)

The protocol derives per-party nonce bases via:

```
nonce_base = SHA3-256([0x05] || party_index || seed)
```

Both Alice and Bob get random-looking 31-bit starting points that increment.
These are **not guaranteed to be disjoint** — they can overlap.

Approximate collision probability if both sides send N chunks each:

| Chunks each | Payload | Collision probability |
|---|---|---|
| 1,000 | ~30 KB | 0.00009% |
| 33,826 | ~1 MB | 0.003% |
| 1,000,000 | ~29.6 MB | 0.093% |
| 5,000,000 | ~147.8 MB | 0.466% |

If nonce reuse occurs under the same seed, the coordinate-masking layer behaves
like a reused one-time pad — the same `S`, masks, and background are reused,
potentially leaking plaintext relationships.

A correct design would partition the nonce space explicitly (e.g., include
direction/sender in every KDF call, or reserve a high bit for sender direction).

---

## Finding 6: Duplicate-Chunk DoS (Low)

The client's chunk reassembly increments `buf.received++` even for duplicate
`chunkIndex` values. Replaying the same chunk index can make finalization trigger
(`buf.received === totalChunks`) while chunks are still missing, causing
client-side breakage or crashes.

---

## Running the PoC

```bash
git clone https://github.com/NateWeav/NDCrypt.git
cd NDCrypt
cargo run --example mitm_poc
```

The only modification to the original repo is adding `"rlib"` to `crate-type`
in `Cargo.toml` so the library can be linked natively (the original is
`cdylib`-only for WASM). All crypto functions used are the original,
unmodified NdCrypt code.

### What the PoC Shows (5 phases)

1. **Phase 1 — Control:** Normal handshake works; seeds match, confirmation passes, messages round-trip.
2. **Phase 2 — Attack:** Mallory forges `c1=0, c2=encode_seed(K_M)`; Alice decapsulates K_M; confirmation passes; UI says "E2EE Tunnel Established."
3. **Phase 3 — Decryption:** Mallory intercepts and decrypts Alice's encrypted message.
4. **Phase 4 — Forgery:** Mallory encrypts a fake message; Alice decrypts it, thinking it's from Bob.
5. **Phase 5 — Full MITM relay:** Mallory holds both session keys (K_M with Alice, K_B with Bob) and transparently relays messages in both directions.

---

## Root Cause

`decapsulate_payload()` in `src/decrypt.rs` has **no ciphertext validation**. It
accepts any `(c1, c2)` pair and decodes whatever polynomial `c2 - c1·s` reduces to
— including attacker-chosen values. Setting `c1 = 0` makes Alice's private key
irrelevant, so the attacker can choose any seed without solving Ring-LWE.

The "key confirmation" layer was intended to catch MITM attacks, but it only
proves the sender knows the seed — which is trivially true when the sender chose
the seed.

## What To Do Instead

The fix is **not** to patch this cipher. Use standard, audited, peer-reviewed
cryptographic building blocks:

- **ML-KEM (Kyber)** or **X25519** for key exchange / KEM
- **HKDF** for key derivation
- **AES-GCM** or **ChaCha20-Poly1305** for authenticated encryption
- **Signatures / identity keys / fingerprint verification** for MITM resistance
- Or use an existing protocol: **Signal**, **Noise**, **MLS**, **age**, **libsodium**

Rolling your own crypto is one of the most dangerous things you can do in software.
Even implementations of well-studied algorithms by experts get broken. The issue
here is not just implementation bugs — it's fundamental cryptographic design flaws
that no amount of careful coding can fix.

---

## Original README (preserved below for reference)

---

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

After the handshake, both parties verify the exchange was not intercepted.

```
CONFIRM_TAG         = fixed byte sequence known to both clients
NONCE_CONFIRM_BOB   = 0x80000000  (bit 31 set — reserved nonce space)
NONCE_CONFIRM_ALICE = 0x80000001
```

Bob encrypts CONFIRM_TAG with NONCE_CONFIRM_BOB and sends it alongside his ciphertext.

Alice decapsulates, derives the same seed, decrypts the confirmation — if it matches CONFIRM_TAG, Bob provably encapsulated against her real public key. A MITM who swapped the public key produces a different seed and cannot produce a matching confirmation. Alice then sends her own confirmation back. Only after both confirmations pass does either side mark the channel secure.

> **⚠️ Security audit note:** The claim above is **false**. See [Finding 2](#finding-2-key-confirmation-defeated-critical) in the security audit section at the top of this README. The confirmation is defeated by the chosen-seed forgery in Finding 1.

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

The Python WebSocket relay routes encrypted frames between peers. It enforces protocol structure but never inspects content.

### Security Features

| Tag | Feature | Description |
|---|---|---|
| S1 | Session pairing | Opaque session_id (random 32 hex chars) routes Bob's reply to the correct Alice. Carries no cryptographic meaning — real integrity is the confirmation round-trip |
| S3 | Origin allowlist | WebSocket upgrades rejected unless Origin matches server's own host. Computed once at startup, not per-connection |
| S4 | Rate limiting | Token bucket per IP: 200 msg/s burst, refills at 100/s. Flood silently dropped |
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

examples/
    └── mitm_poc.rs   — MITM proof-of-concept (this fork)
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

### Run the relay server

```bash
python server.py
# http://localhost:8080        local
# http://<your-ip>:8080        LAN peers
```

### Run the MITM PoC

```bash
cargo run --example mitm_poc
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

> **⚠️ Security audit note:** Layer 3 is **broken**. The chosen-seed forgery
> (Finding 1) allows a MITM to pass the confirmation check while controlling
> the shared secret. See the security audit section at the top of this README.

### Known Limitations

**IND-CPA only.** The Ring-LWE KEM does not include the Fujisaki-Okamoto transform. It provides IND-CPA security — adequate for ephemeral key exchange with forward secrecy, not IND-CCA2. Private keys must not be reused across sessions.

**StdRng.** gka.rs uses Rust's StdRng (ChaCha12) for the Fisher-Yates shuffle. Pinning to ChaCha20Rng via rand_chacha would make the algorithm explicit for production.

**Expansion ratio.** NDCrypt produces 2048 bytes of ciphertext per 31 bytes of plaintext (~66× expansion). For large file transfers this is significant. The protocol is designed for secure messaging.

**Two-party only.** One Alice and one Bob per session. Group chat requires a separate key agreement protocol.

> **⚠️ Security audit note:** The IND-CPA limitation is more severe than stated
> here. Because there is no FO transform AND no ciphertext validation at all,
> the KEM is not even IND-CPA secure against active attackers — an attacker
> can choose the shared secret via a forged ciphertext.
