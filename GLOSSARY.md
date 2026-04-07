# CESS glossary

Short explanations for readers who are not cryptography specialists. Normative rules always live in `spec/CESS-v0.2.md` and `ALGORITHM-REGISTRY.md`; this page is a plain-language aid only.

## A

**AEAD (authenticated encryption with associated data)**  
Encryption that both hides the payload and spots tampering. If someone flips bits in transit, decryption fails instead of producing garbage silently.

**Air-gapped**  
A computer or workflow kept off networks on purpose, so secrets are generated or split without exposure to the internet.

**Algorithm**  
In CESS, a named recipe for the mathematics used (for example how to encrypt a block or agree on a key). The standard does not lock you to one cipher family; see *cipher-agnostic*.

**Algorithm registry**  
The living list in `ALGORITHM-REGISTRY.md` of which algorithms are approved, excluded, or provisional for CESS, and how *suite identifiers* are assigned.

**Argon2id**  
A password-hashing method designed to be slow and memory-hard so guessing passwords from stolen data is expensive. CESS uses it when shares are protected by a PIN or password.

**Audit (cryptographic)**  
Independent expert review of a design or implementation. CESS expects serious primitives to have multiple independent audits before full approval.

## B

**BLAKE3**  
A fast modern hash function family. In CESS it is used for integrity checks, keyed tags, and as the hash inside HKDF-style key derivation (HKDF-BLAKE3).

**Brainpool (for example BrainpoolP384r1, BrainpoolP512r1)**  
Families of elliptic curves used for public-key agreement in CESS. They are used instead of certain NIST curves that CESS policy excludes.

## C

**Cascade**  
Applying more than one encryption layer in a fixed order (for example an inner AEAD and an outer block cipher plus integrity). CESS registers several cascade shapes in the algorithm registry.

**CESS-PQ**  
The optional part of CESS that adds post-quantum key exchange on top of classical cryptography, following the spec’s hybrid rules.

**ChaCha20-Poly1305**  
A common combination: ChaCha20 hides data; Poly1305 detects changes. CESS uses it for the *Mode A* outer wrapper and as one of the inner bulk options.

**Cipher-agnostic**  
The splitting, wrapping, and envelope parts of CESS are fixed, but bulk encryption and related choices come from the registry. Products can move between approved algorithms without changing the overall secret-sharing story.

**Conformance**  
A product or library “conforms” to CESS when it follows the normative spec and documents how it does so; see `CONFORMANCE.md`.

## D

**Digital signature**  
A short proof attached to data showing it was approved by a holder of a private key. CESS may use Ed25519 signatures over inner payloads in registered profiles.

## E

**ECDH (Elliptic Curve Diffie-Hellman)**  
A way for two parties to agree on a shared secret over an open channel using elliptic-curve public keys. CESS uses Brainpool curves for classical agreement in defined places.

**Ed25519**  
A compact digital signature scheme with strong real-world use and analysis. It appears in CESS as an optional inner-profile signing method where the registry allows it.

**Envelope**  
The structured package around a share or message: headers, ciphertext, integrity tags, and so on, as defined by the standard.

## G

**GF(2^8)**  
A finite field where each value is essentially one byte. Shamir’s scheme in CESS is defined over this field so implementations can work byte by byte.

## H

**Hard exclusion list**  
Algorithms CESS policy does not allow in the selectable layer (for example certain NIST-mandated curves or digests), with reasons given in the specification.

**HKDF; HKDF-BLAKE3**  
Key derivation: turning one shared secret into several application keys in a standard way. CESS specifies HKDF structure with HMAC-BLAKE3 as the core PRF (“HKDF-BLAKE3”).

## I

**Inner layer; outer layer**  
The *inner* layer encrypts the sensitive payload (shares, metadata rules permitting). The *outer* layer may wrap that again for transport so observers learn less about what is inside.

**Integrity tag**  
A short value attached to ciphertext so any change to the data is detected when decrypting or verifying.

## K

**KDF (key derivation function)**  
Derives one or more keys from an input secret using a defined recipe (see HKDF-BLAKE3).

**KEM (key encapsulation mechanism)**  
A public-key method to deliver a fresh symmetric key to a peer. Classical Brainpool and optional post-quantum KEMs appear in CESS hybrid profiles.

**k-of-n (threshold)**  
You need *k* shares out of *n* total to reconstruct the secret; fewer than *k* reveals no useful information in the ideal Shamir model.

## M

**MAC (message authentication code)**  
A short tag proving data was not altered and was produced with a shared secret key. Poly1305 is an example used next to stream ciphers.

**Mode A; Mode B**  
*Mode A* uses a fixed outer ChaCha20-Poly1305 wrapper so the cipher suite id is not visible in clear on the wire before decryption. *Mode B* covers cases where the suite is fully agreed beforehand so less of that wrapper is needed on the wire.

## N

**Nonce**  
A value that must not repeat for the same key in a given use. Reusing a nonce with the same key breaks security for most AEAD constructions.

**Normative**  
Text that uses RFC 2119 words (MUST, SHOULD, and so on) and defines what implementations are required to do. Contrast with *informative* notes that explain intent without adding new requirements.

## O

**Open Invention Network (OIN)**  
An organisation that runs a defensive patent pool around Linux-related open source. CESS is registered with OIN; see `README.md` and `PATENTS.md` for how that relates to contributors.

## P

**PIN wrapping**  
Deriving a key from a user PIN (via Argon2id and HKDF-BLAKE3 in CESS) and encrypting a share so possession of the PIN is needed to unwrap it.

**Poly1305**  
A one-time authenticator often paired with ChaCha20 or with block ciphers in CTR mode to form an integrity tag.

**Post-quantum (PQ)**  
Algorithms believed to resist attacks by large quantum computers. CESS can combine them with classical steps in a hybrid way; see CESS-PQ.

**Prior art**  
Earlier published work that shows an idea was already known. Publishing specifications and analysis openly helps establish prior art for patent purposes.

**Primitive**  
A basic building block (hash, block cipher, elliptic-curve operation) used inside a larger protocol.

## R

**RFC 2119**  
The standard that defines words like MUST, MUST NOT, SHOULD, and MAY in internet specifications. CESS normative text uses those keywords deliberately.

## S

**Secret sharing**  
Splitting a secret into several *shares* so only a quorum can rejoin them.

**Shamir’s Secret Sharing**  
A concrete mathematical method (polynomials over a finite field) to split a secret into *n* shares with a *k-of-n* threshold. CESS fixes this for bytes via GF(2^8).

**Suite identifier (suite_id)**  
A 16-bit code that tells software which registered cipher profile (curves, bulk ciphers, options) is in use for a message. In Mode A it is carried inside authenticated outer plaintext, not as cleartext framing.

## T

**Test vector**  
Published example inputs and expected outputs so independent programs can check they implement the math the same way. CESS ships many in `vectors/`.

**Threshold**  
The minimum number of shares *k* required to recover the secret in a *k-of-n* scheme.

**Token (hardware)**  
A USB gadget, smartcard, or similar device that can store keys or run crypto operations; CESS discusses bindings where relevant.

**Twofish; Serpent**  
Block ciphers available as registered options for inner bulk encryption and cascades, with test vectors in the repository.

## X

**X25519**  
An optional curve25519-based key agreement listed as permitted in the registry with documentation; it is not the default Mode A outer ECDH, which uses BrainpoolP384r1 per spec.
