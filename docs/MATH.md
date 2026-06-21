# The Mathematics Behind Personal Notary

> A rigorous-but-readable companion to [GUIDE.md](GUIDE.md). It explains *why* the notary is
> sound, with the actual mathematics, the security arguments, and a curated reading list of the
> primary sources. GitHub renders the equations.

> **Why fundamentals, now more than ever.** In an era where code and prose can be generated on
> demand, the scarce skill is *judgement grounded in first principles* — knowing which guarantees
> a system really provides and which it only appears to. Cryptography is the sharpest example:
> every line here rests on a small number of hard mathematical problems and precise security
> definitions. Understand those, and the whole edifice (and its failure modes) becomes legible.
> That understanding is exactly what does **not** become obsolete.

## Map: which mathematics underpins which part

| Notary component | Mathematical foundation |
|------------------|--------------------------|
| SHA-256 fingerprint (`Hashing`) | Cryptographic hash functions; Merkle–Damgård; collision/preimage resistance; the birthday bound |
| Sign / verify (`*SigningProvider`, `VerifyBytes`) | Public-key cryptography; the hash-and-sign paradigm; EUF-CMA security |
| ECDSA on P-256 | Finite fields $\mathbb{F}_p$, the elliptic-curve group, the elliptic-curve discrete-log problem (ECDLP) |
| X.509 certificate (`.cert`) | Chains of trust / PKI; signatures over a structured identity |
| RFC 3161 timestamp (`.tsr`) | A signature over (hash + time) by a trusted authority; CMS/ASN.1 encoding |

---

## 1. Hash functions — the fingerprint

A cryptographic hash $H:\{0,1\}^* \to \{0,1\}^n$ (here $n=256$) compresses arbitrary input to a
fixed digest. Three security properties matter:

- **Preimage resistance:** given $y$, hard to find $x$ with $H(x)=y$ — work $\approx 2^{n}$.
- **Second-preimage resistance:** given $x$, hard to find $x'\neq x$ with $H(x')=H(x)$ — $\approx 2^{n}$.
- **Collision resistance:** hard to find *any* $x\neq x'$ with $H(x)=H(x')$.

### The birthday bound
Collision resistance is the weakest because of the **birthday paradox**: among $k$ random digests
the expected number of colliding pairs is $\binom{k}{2}/2^{n}$, so a collision appears once
$k \approx 2^{n/2}$. For SHA-256 that is $2^{128}$ — infeasible. *This is why a 256-bit hash gives
"128-bit" collision security*, and why the notary's tamper-evidence holds: you cannot craft a
different document with the same digest, so a valid signature over the digest pins the exact bytes.

### Construction (Merkle–Damgård)
SHA-256 pads the message (length-encoded), splits it into 512-bit blocks $m_1,\dots,m_t$, and
iterates a compression function $f$ from a fixed initialization vector:

$$h_0 = \text{IV}, \qquad h_i = f(h_{i-1}, m_i), \qquad H(m) = h_t.$$

The **Merkle–Damgård theorem** says: if $f$ is collision-resistant, so is $H$. That reduction — a
big guarantee from a small one — is the template for the whole field. (SHA-256's $f$ uses modular
additions, rotations, and XORs; the length padding closes off length-extension-style collisions.)

➡️ In code: [`Hashing.cs`](../src/Notary.Core/Hashing.cs) — everything downstream signs only this 32-byte value.

---

## 2. Public-key signatures — proving *who* and *unchanged*

### The idea
A **key pair** $(d, Q)$: a private $d$ signs, a public $Q$ verifies. Diffie & Hellman (1976) introduced
the concept; RSA (1978) gave the first concrete scheme. A signature scheme is a triple
$(\textsf{Gen}, \textsf{Sign}, \textsf{Vrfy})$ with the correctness requirement
$\textsf{Vrfy}_Q(m, \textsf{Sign}_d(m)) = 1$.

### What "secure" means (EUF-CMA)
The gold-standard definition (Goldwasser–Micali–Rivest, 1988) is **existential unforgeability under
adaptive chosen-message attack**: an adversary who may request signatures on messages of its choice
still cannot produce a *new* valid (message, signature) pair, except with negligible probability.
Anything weaker is a footgun.

### Hash-and-sign
We never sign the document — we sign $H(\text{document})$. Beyond efficiency, this is what makes the
scheme work on arbitrary-length inputs and underlies the security proofs (the "full-domain hash" /
random-oracle analyses of Bellare–Rogaway, 1993). It also means: change one bit of the file → its
hash changes (§1) → the existing signature no longer verifies. **Tamper detected.**

➡️ In code: [`NotaryService.SignBytes`](../src/Notary.Core/NotaryService.cs) hashes then calls
`ISigningProvider.SignHash`; verification recomputes the hash and checks the signature against the
**public** key in the certificate.

---

## 3. Elliptic curves & ECDSA — the engine

This project uses **ECDSA on NIST P-256** (a.k.a. `secp256r1`/`prime256v1`).

### The group
Work over a prime field $\mathbb{F}_p$ ($p$ a 256-bit prime). The curve is

$$E:\; y^2 = x^3 + ax + b \pmod p,$$

and its points (plus a point at infinity $\mathcal{O}$) form an **abelian group** under the chord-and-tangent
addition law. Fix a base point $G$ of large prime order $n$. "Scalar multiplication"
$kG = \underbrace{G + G + \cdots + G}_{k}$ is efficient (double-and-add).

### The hard problem (ECDLP)
Given $Q = dG$, recovering $d$ is the **elliptic-curve discrete-logarithm problem**. No
sub-exponential algorithm is known for well-chosen curves; the best generic attack (Pollard's rho)
costs $\approx \sqrt{n} \approx 2^{128}$ for P-256. That single hardness assumption is what keeps the
private key private. Koblitz and Miller independently proposed EC cryptography (1985–87); the payoff
is **much smaller keys** than RSA for the same security (256-bit EC ≈ 3072-bit RSA).

### Signing and verifying
Keys: private $d \in [1, n-1]$, public $Q = dG$. To sign message $m$ with hash $e = H(m)$ (leftmost
bits truncated to $\lceil \log_2 n\rceil$):

$$
\begin{aligned}
&\text{pick random } k \in [1, n-1], \quad R = kG, \quad r = x_R \bmod n,\\
&s = k^{-1}\,(e + r\,d) \bmod n. \qquad \text{Signature} = (r, s).
\end{aligned}
$$

Verify, given $(r,s)$, $e$, and $Q$:

$$
w = s^{-1} \bmod n,\quad u_1 = e\,w \bmod n,\quad u_2 = r\,w \bmod n,\quad
(x_1, y_1) = u_1 G + u_2 Q,
$$

and **accept iff** $x_1 \equiv r \pmod n$.

**Why it works.** From $s = k^{-1}(e + rd)$ we get $k = s^{-1}(e + rd) = u_1 + u_2 d$. Hence

$$u_1 G + u_2 Q = u_1 G + u_2 d\,G = (u_1 + u_2 d)\,G = kG = R,$$

so $x_1 = x_R = r$. Only the holder of $d$ could have produced an $s$ that collapses back to $R$. ∎

### The per-signature nonce $k$ — the sharpest pitfall
$k$ must be **secret and unique** per signature. If you ever reuse $k$ across two signatures
$(r, s_1)$ and $(r, s_2)$ on hashes $e_1, e_2$:

$$s_1 - s_2 = k^{-1}(e_1 - e_2) \;\Rightarrow\; k = \frac{e_1 - e_2}{s_1 - s_2} \bmod n,$$

and then $d = r^{-1}(s_1 k - e_1) \bmod n$ — **full private-key recovery**. This is exactly how the
2010 Sony PlayStation 3 signing key was extracted (a fixed $k$). The modern defense is **deterministic
ECDSA** (RFC 6979), which derives $k$ from the private key and message via HMAC — no randomness to get
wrong. *Worth knowing precisely, because it's the kind of subtlety that separates "uses crypto" from
"understands crypto."*

### Signature format
.NET's `ECDsa.SignHash` / `VerifyHash` use the fixed-size **IEEE P1363** encoding $r \,\|\, s$ (64 bytes
for P-256) — which is why the local provider and Azure Key Vault's `ES256` are interchangeable on the
verify side (see [GUIDE.md](GUIDE.md) Q8). (ASN.1/DER is the other common encoding, used inside the CMS token.)

➡️ In code: [`LocalKeySigningProvider`](../src/Notary.Core/LocalKeySigningProvider.cs),
[`KeyVaultSigningProvider`](../src/Notary.Core/KeyVaultSigningProvider.cs).

---

## 4. Trust & time — PKI and RFC 3161

### Certificates and chains of trust
A raw public key is anonymous. An **X.509 certificate** is a signed statement binding a key to an
identity and a validity window; verifying a signature means checking a *chain* up to a trusted anchor.
Here the certificate is **self-signed** (the key vouches for itself) — fine for a personal notary; in
production a CA's signature roots the trust. Standard: **RFC 5280**.

### Trusted timestamping (the `.tsr`)
A signature proves *what* and *who*, not *when*. A **Time-Stamp Authority (TSA)** is a trusted clock:
you send it the **messageImprint** $H(\text{doc})$; it returns a token asserting "I saw this digest at
time $t$," signed by a key whose certificate carries the **`timeStamping`** extended-key-usage. The
token is a CMS `SignedData` (RFC 5652) wrapping a `TSTInfo` structure (RFC **3161**, with the
ESSCertIDv2 update in RFC 5816), all DER-encoded (ASN.1).

Crucially, verification checks the TSA's signature **and** that the token's imprint equals the file's
*current* hash — so tampering breaks the timestamp too, not just the signature. It composes the same
hash-then-sign trust you already understand, with a second signer whose only claim is about time.

➡️ In code: [`LocalTimestampAuthority`](../src/Notary.Core/LocalTimestampAuthority.cs) (issues tokens),
[`Timestamping.Verify`](../src/Notary.Core/Timestamping.cs) (checks them).

---

## 5. Curated reading list (primary sources)

> Tiered from foundational → standards → "understand the failures." Titles are stable; search by
> title if a link rots.

### A. Textbooks (start here)
- **Handbook of Applied Cryptography** — Menezes, van Oorschot, Vanstone (CRC, 1996). *Free:* <https://cacr.uwaterloo.ca/hac/>. Ch. 9 (hashes), Ch. 11 (signatures). The reference.
- **A Graduate Course in Applied Cryptography** — Boneh & Shoup. *Free:* <https://toc.cryptobook.us/>. Modern, proof-oriented, rigorous security definitions.
- **Introduction to Modern Cryptography** — Katz & Lindell (3rd ed., 2020). The cleanest treatment of definitions (EUF-CMA, reductions).
- **Guide to Elliptic Curve Cryptography** — Hankerson, Menezes, Vanstone (Springer, 2004). The EC implementation bible.

### B. Foundational papers
- Diffie & Hellman, **"New Directions in Cryptography"**, *IEEE Trans. IT*, 1976 — invents public-key crypto.
- Rivest, Shamir, Adleman, **"A Method for Obtaining Digital Signatures and Public-Key Cryptosystems"**, *CACM*, 1978 — RSA.
- Goldwasser, Micali, Rivest, **"A Digital Signature Scheme Secure Against Adaptive Chosen-Message Attacks"**, *SIAM J. Computing*, 1988 — the EUF-CMA definition.
- Koblitz, **"Elliptic Curve Cryptosystems"**, *Math. of Computation*, 1987; Miller, **"Use of Elliptic Curves in Cryptography"**, *CRYPTO '85* — EC cryptography.
- Johnson, Menezes, Vanstone, **"The Elliptic Curve Digital Signature Algorithm (ECDSA)"**, *Int. J. Information Security*, 2001 — the canonical ECDSA paper.
- Damgård, **"A Design Principle for Hash Functions"**, *CRYPTO '89*; Merkle, **"One Way Hash Functions…"** — the Merkle–Damgård construction.
- Bellare & Rogaway, **"Random Oracles are Practical"**, *CCS '93* — the hash-and-sign / FDH analysis.

### C. Standards & specifications
- **FIPS 180-4** — Secure Hash Standard (defines SHA-256).
- **FIPS 186-5** (2023) — Digital Signature Standard (ECDSA, EdDSA; supersedes 186-4).
- **SEC 1 / SEC 2** (SECG) — Elliptic Curve Cryptography & named curves (P-256 = `secp256r1`).
- **RFC 6979** — Deterministic ECDSA (the nonce fix). *Read this one closely.*
- **RFC 5280** (X.509 PKI), **RFC 5652** (CMS), **RFC 3161** + **RFC 5816** (Time-Stamp Protocol).

### D. Understand the failures (the best teacher)
- **fail0verflow, "Console Hacking 2010" (27C3)** — the PS3 fixed-nonce ECDSA key recovery. The §3 nonce algebra, live.
- **RFC 6979 §1** — a crisp statement of *why* ECDSA nonce handling is dangerous and how to remove the risk.

---

## 6. A suggested study path
1. **Hashing** — HAC Ch. 9; internalize the birthday bound and Merkle–Damgård. Map it to `Hashing.cs`.
2. **Signatures & definitions** — Katz–Lindell on EUF-CMA; the hash-and-sign paradigm. Map to `SignBytes`/`VerifyBytes`.
3. **Elliptic curves** — Hankerson Ch. 1–4 (or Boneh–Shoup's EC chapter); derive the ECDSA verify identity yourself (it's in §3 above).
4. **The nonce pitfall** — RFC 6979 + the PS3 talk. Then look at how a real signer (Key Vault) removes that worry from your code.
5. **Trust & time** — RFC 5280 then RFC 3161; trace `LocalTimestampAuthority` building a token field-by-field.

> Checkpoint: you understand this project when you can answer, from first principles, *exactly why*
> flipping one byte of a notarized file makes both the signature and the timestamp fail — and *what
> hard problem* an attacker would have to solve to forge either. (Answer key: §1 birthday bound + §3
> ECDLP.)
