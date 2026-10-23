# Zklaim wire format, version 2

Version 2 uses RFC 8032 Ed25519 signatures, explicit integer encodings, and two message kinds: credentials for confidential issuer-to-prover transfer, and presentations for verifiers. No C structures, padding, enum storage, native integers, or native GMP limbs are copied onto the wire.

Compared to version 1, messages no longer carry a verification key, payload salts are 15 bytes instead of 8, and every proof is bound to a verifier-chosen nonce. See [Migration](#migration).

All binary multibyte integers are unsigned and big-endian. Keys, hashes, signatures, and witness blocks are byte strings. The lengths below are octets. Decoders require the exact total length, reject unsupported versions, kinds, curves, operations, and reserved values, and leave the destination unchanged on failure.

## Header

The header is exactly 88 bytes.

| Offset | Length | Meaning |
| --- | --- | --- |
| 0 | 4 | ASCII `ZKLM` |
| 4 | 2 | Version, `2` |
| 6 | 1 | Kind: `1` credential, `2` presentation |
| 7 | 1 | SNARK curve: `1` ALT_BN128, `2` BN128, `3` EDWARDS, `4` MNT4, `5` MNT6 |
| 8 | 4 | Payload count |
| 12 | 4 | Proof length, zero if absent |
| 16 | 8 | Reserved, must be zero |
| 24 | 32 | Issuer public key in RFC 8032 encoding |
| 56 | 32 | SHA-256 of header bytes 0 through 55 |

The curve must match the receiving library's configured curve. The header hash detects corruption; it does not authenticate a message. Authentication requires `zklaim_ctx_verify` with a separately trusted issuer key and verification key, verifier-selected predicates, and the verifier's nonce.

The body contains the payload records in order, followed by the 64-byte issuer signature and the proof. Record sizes depend only on the message kind.

## Payload records

A presentation payload is exactly 77 bytes:

| Offset | Length | Meaning |
| --- | --- | --- |
| 0 | 40 | Five reference values, each an 8-byte big-endian integer |
| 40 | 5 | Five operation codes, one byte each |
| 45 | 32 | SHA-256 attribute commitment |

The operation codes are `1` less, `3` less-or-equal, `2` equal, `10` greater-or-equal, `8` greater, `9` not-equal, and `99` noop. Other codes are invalid. They are protocol values independent of the compiler's enum representation.

Presentations have no privacy flag, attribute pre-image, or salt fields. `zklaim_ctx_serialize` always writes this kind, even when the source still contains witnesses. Deserialization sets `priv = 1` and zeroes `pre` and `salt`.

A credential payload is exactly 133 bytes: the same 77 public bytes, followed by one privacy flag and a 55-byte witness block. Flag `0` means a witness is present. Flag `1` means hidden; all 55 witness bytes must then be zero. The witness block contains five 8-byte big-endian attribute values followed by a 15-byte random salt. Its SHA-256 is the commitment. The salt is not encoded a second time; the in-memory `salt` field is reconstructed from the witness.

The salt provides 120 bits of hiding even for low-entropy attributes. 55 bytes is the longest message that SHA-256 pads into a single 64-byte block (55 bytes, the `0x80` byte, and the 8-byte length), so the circuit still needs one compression per payload.

Use `zklaim_ctx_serialize_credential` only for confidential issuer-to-prover transfer. `zklaim_set_attr` and `zklaim_get_attr` write and read the canonical witness representation. Callers must not use native integer `memcpy` to interpret `pre`. Hashing, public-input mapping, and the comparison circuit use the same representation.

## SNARK keys and proofs

The circuit depends only on the payload count. An issuer runs `zklaim_trusted_setup` once per supported count and reuses the keys for every credential with that count. Provers receive the proving key; verifiers pin the verification key per issuer and payload count, in the same way as the issuer public key. Neither key appears in credentials or presentations. Whoever runs the setup can forge proofs for its circuit, so verifiers must trust that party; for an issuer-run setup this is the issuer, who is trusted to issue credentials anyway.

The proof's public input contains, for each payload in order, the 256-bit commitment, the five references, and the operation flags, followed by the verifier's 32-byte nonce, bit for bit as transmitted. `zklaim_proof_generate` and `zklaim_ctx_verify` take the nonce as an argument; it is never read from a message. A verifier must choose a fresh random nonce for every request. A proof for one nonce does not verify for another, so a presentation forwarded by a verifier cannot be reused elsewhere. The nonce does not identify the verifier, so it does not prevent a party from relaying a live challenge to the holder.

A proving key is rejected unless its embedded constraint system equals the circuit for the context's payload count (allowing the A/B swap that libsnark's generator may apply) and its vectors have the sizes the prover indexes. A verification key for another payload count fails verification.

Version 2 fixes the pinned libsnark/libff decimal serialization with standard field values and uncompressed points: `BINARY_OUTPUT=OFF`, `MONTGOMERY_OUTPUT=OFF`, and `USE_PT_COMPRESSION=OFF`. These are protocol settings, enforced for libff and its consumers. Decimal numbers and collection counts use ASCII digits and the classic C locale; separators follow the pinned libsnark serializers. Native limb dumps and Montgomery residues are excluded. Import requires an exact canonical re-encoding and validates proof points and verification-key point/vector structure.

This encoding preserves the same field values across byte orders and GMP word sizes. The curve identifier and protocol version select the encoding; changing these serializers requires a new protocol version. Proving keys, transferred separately to provers, use the same canonical decimal format. Wire lengths and counts must fit 32 bits, with all allocation arithmetic additionally checked against the receiving platform's `size_t`.

## Issuer signatures and keys

`zklaim_sign` and `zklaim_verify` use pure Ed25519 over the supplied message bytes, with SHA-512 and deterministic nonce derivation handled by EdDSA. There is no external SHA-256 prehash. Public keys are 32-byte RFC 8032 points. Signatures are the 32-byte encoded point R followed by the 32-byte little-endian scalar S, copied as byte strings without MPI integer conversions.

The message signed by `zklaim_ctx_sign` has a 12-byte prefix followed by the payload commitments:

| Offset | Length | Meaning |
| --- | --- | --- |
| 0 | 4 | ASCII `ZKSG`, signature domain |
| 4 | 2 | Protocol version, `2` |
| 6 | 1 | Signature algorithm, `1` Ed25519 |
| 7 | 1 | SNARK curve identifier |
| 8 | 4 | Payload count |
| 12 | count × 32 | Commitments in payload order |

Predicates remain selectable public inputs to the proof; the verifier must supply its expected predicates to `zklaim_ctx_verify`. The verification key is not signed: verifiers pin it, so an issuer can replace its setup without reissuing credentials.

The private-key container returned by `zklaim_pk2buf` is zklaim-specific: 32 public-key bytes followed by the 32-byte RFC 8032 seed. It is not PKCS#8 and is not the old ECDSA scalar encoding. Import checks that the seed and public key agree. Generated and imported keys use libgcrypt's explicit `eddsa` flag. Legacy ECDSA keys and signature objects are rejected.

The wrapper checks the RFC 8032 scalar bound `S < L` on import, export, and verification, including direct S-expression calls. Seed/public-key agreement is checked by independently deriving the public key with OpenSSL. These checks do not depend on whether the installed libgcrypt version enforces them itself.

## Migration

Version 1 and unversioned raw-struct messages are rejected; there is no heuristic or fallback decoder.

From version 1:

- Run one trusted setup per issuer and supported payload count with `zklaim_trusted_setup(count, &pk, &pk_size, &vk, &vk_size)`. Distribute the proving key to provers and pin the verification key at verifiers. `zklaim_ctx` no longer has `pk` or `vk` fields.
- Reissue all credentials. The salt grew to 15 bytes, which changes every commitment, and the circuit gained the nonce input, which requires new setup keys. Issuer signing keys stay valid.
- Verifiers send a fresh random `ZKLAIM_NONCE_SIZE`-byte nonce with every predicate request and pass it, with the pinned verification key, to `zklaim_ctx_verify`. Provers pass the nonce and proving key to `zklaim_proof_generate`.

From unversioned messages, additionally regenerate issuer signing keys and pin their new public keys. Existing private ECDSA scalars must not be relabeled as Ed25519 seeds.

Use the explicit credential serializer when handing witnesses to a prover. Use the default serializer for every presentation; clearing witnesses beforehand remains useful for in-memory hygiene but is not required to prevent serialization leaks. The trusted issuer and predicate arguments of `zklaim_ctx_verify` remain mandatory.

The Ed25519 implementation is checked against [RFC 8032 section 7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1) and OpenSSL's independent implementation. The libgcrypt inputs follow its [EdDSA signing interface](https://www.gnupg.org/documentation/manuals/gcrypt/Cryptographic-Functions.html).
