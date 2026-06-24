# NDCrypt

**NDCrypt** is a hybrid cryptographic implementation written in Rust. It pairs a **Ring Learning With Errors (Ring-LWE) Key Encapsulation Mechanism (KEM)** with a deterministic, steganographic symmetric stream cipher. 

This architecture isolates the computationally heavy lattice algebra strictly to the initial handshake phase. Once a 32-byte shared root seed is securely established, the protocol transitions to an ultra-low-latency symmetric cipher that camouflages data within a uniform modulo distribution.

## 📐 Mathematical Parameters

All Phase 1 lattice operations occur within the polynomial quotient ring:
$$R_q = \mathbb{Z}_q[X]/(X^N + 1)$$

* **Degree ($N$):** 1024
* **Modulus ($q$):** 12289 (A prime that supports the Number Theoretic Transform)
* **Signal Capacity:** 32 bytes per payload
* **Encoding Scalar:** $\lfloor q/2 \rfloor = 6144$
* **Noise Distribution ($\chi$):** Centered Binomial Distribution (CBD) producing coefficients in $\{-2, -1, 0, 1, 2\}$.

## 🌊 Protocol Flow & Algebra

NDCrypt is decoupled into two phases. The asymmetric lattice math never touches the payload, and the symmetric cipher never touches the network handshake.

### Phase 1: Ring-LWE Key Encapsulation (`encrypt.rs`, `decrypt.rs`)

**1. Key Generation (`keygen.rs`)**
Alice generates a uniform polynomial $a \leftarrow R_q$. She samples a secret key polynomial $s \leftarrow \chi$ and an error polynomial $e \leftarrow \chi$. 
She computes her public key $b$:
$$b = a \cdot s + e \pmod q$$
* **Public Key:** $(a, b)$
* **Private Key:** $s$

**2. Encapsulation (`encrypt.rs`)**
Bob generates a random 32-byte root seed. He encodes this seed into a message polynomial $m \in R_q$ by mapping binary `0` to $0$ and binary `1` to $6144$. 
Bob samples ephemeral noise polynomials $s', e', e'' \leftarrow \chi$. He creates the ciphertext pair $(c_1, c_2)$:
$$c_1 = a \cdot s' + e' \pmod q$$
$$c_2 = b \cdot s' + e'' + m \pmod q$$
* **Ciphertext sent to Alice:** $(c_1, c_2)$

**3. Decapsulation (`decrypt.rs`)**
Alice receives $(c_1, c_2)$ and computes the noisy message polynomial using her private key $s$:
$$c_2 - c_1 \cdot s \pmod q$$
Because $b = a \cdot s + e$, the equation expands and the $(a \cdot s \cdot s')$ terms cancel out, leaving:
$$m + (e \cdot s' + e'' - e' \cdot s) \pmod q$$
The term $(e \cdot s' + e'' - e' \cdot s)$ is the residual lattice noise. Because the noise coefficients are small relative to $q$, Alice evaluates each coefficient of the resulting polynomial. If the coefficient falls within the threshold $(q/4, 3q/4)$, it is decoded as a `1`. Otherwise, it is decoded as a `0`. The 32-byte seed is perfectly recovered.

### Phase 2: Symmetric Steganography (`ndcrypt.rs`)

Once the 32-byte seed is synchronized, NDCrypt switches to symmetric encryption using a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG).

**1. Signal Index Derivation**
The root `seed`, a unique `nonce`, and a domain separation tag (`[0x01]`) are hashed via SHA3-256. The resulting digest seeds a CSPRNG (`StdRng`). 
A partial Fisher-Yates shuffle is performed on an array of indices $[0, N-1]$ to deterministically select and sort 32 unique coordinate indices. These represent the hidden physical locations of the payload inside the final polynomial.

**2. Background Generation**
A separate CSPRNG stream (seeded with a domain tag of `[0x03]`) utilizes rejection sampling to populate a 1024-element array with a perfectly uniform distribution of integers in the range $[0, q-1]$.

**3. Masking and Embedding**
A third CSPRNG stream (`[0x04]`) generates uniform mask values. For each byte of the payload $p_i$, Bob locates the corresponding hidden coordinate $idx_i$ and computes the modular addition:
$$\text{Ciphertext}[idx_i] = (p_i + \text{mask}_i) \pmod q$$

Because the addition of a constant to a uniform distribution modulo $q$ results in a uniform distribution, the embedded signal coordinates are statistically indistinguishable from the background noise. The final 1024-element array is transmitted as the payload.

## 🏗️ Core Dependencies

* `concrete-ntt`: Provides $O(N \log N)$ polynomial multiplication utilizing the Number Theoretic Transform.
* `subtle`: Ensures constant-time execution during decapsulation branching to mitigate timing side-channel attacks.
* `zeroize`: Enforces strict memory hygiene, automatically scrubbing private keys ($s$) and root seeds from RAM when they fall out of scope.
* `sha3` / `rand`: Drives the deterministic CSPRNG streams for Phase 2 masking and index shuffling.

## ⚠️ Implementation Security Notes

1. **IND-CPA Security Model:** The Ring-LWE KEM implemented here is strictly **IND-CPA secure** and lacks the Fujisaki-Okamoto (FO) transform. It is explicitly designed for **ephemeral key exchange** (Forward Secrecy). Reusing the same private key $s$ for multiple decapsulations against an active adversary exposes the system to Chosen-Ciphertext Attacks (CCA2).
2. **CSPRNG Determinism:** `ndcrypt.rs` currently utilizes Rust's `StdRng`. For cross-platform production builds, this must be pinned to a specific algorithm (e.g., `ChaCha20Rng` via `rand_chacha`) to guarantee stream reproducibility across different compiler versions and architectures.

