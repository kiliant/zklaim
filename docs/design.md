# Design

This page describes the cryptographic construction, the circuit, and its cost. The byte-level encodings are specified in the [wire format](wire-format.md).

## Building blocks

| Purpose | Choice | Implementation |
| --- | --- | --- |
| Proof system | Groth16 zk-SNARK, verified with the strong input-consistency check | libsnark `r1cs_gg_ppzksnark` |
| Pairing curve | Build option `CURVE`, default `ALT_BN128` (BN254) | libff |
| Commitments | SHA-256 over attributes and a 120-bit salt | libgcrypt natively, libsnark's SHA-256 compression gadget in the circuit |
| Issuer signatures | Ed25519 (RFC 8032), pure, no prehash | libgcrypt, with seed and key checks against OpenSSL |

libsnark and its dependencies are pinned as Git submodules. Only libff is compiled; the parts of libsnark that zklaim uses are header-only and are compiled into `libzklaim`.

## The proven statement

For `n` payloads, the public input consists of, for each payload `i`, its commitment `h_i`, references `R_i`, and operation flags `F_i`, followed by the verifier's nonce `N`. The prover shows that it knows 55-byte pre-images `p_1 … p_n` such that, for every payload `i`:

- `SHA-256(p_i) = h_i`, and
- for each attribute `k` from 0 to 4, with `a_ik` the big-endian integer in bytes `8k … 8k+7` of `p_i`, exactly one flag in `F_ik` is set, and the comparison of `a_ik` with `R_ik` that it selects holds.

The nonce takes part in no comparison. Because it is part of the public input, a proof verifies only for the nonce it was generated with.

The verifier computes the public input itself from the presentation's commitments, its own predicates, and its nonce. The issuer signature over the commitments is checked outside the circuit.

## Public input layout

Each payload contributes 1,280 bits, followed by 256 bits of nonce:

| Bits | Content |
| --- | --- |
| 256 | Commitment `h_i` |
| 512 | References: eight 64-bit big-endian slots; slots 0–4 hold attributes 0–4, slots 5–7 are zero |
| 512 | Operation flags: eight groups of eight bytes; group `k` holds attribute `k`'s flags as one byte each (1 if set, otherwise 0) in the order less, less-or-equal, equal, greater-or-equal, greater, not-equal, noop; groups 5–7 and each group's last byte are zero |
| 256 | Nonce `N`, after the last payload |

The bit string is packed into field elements of `FieldT::capacity()` bits each (253 bits for ALT_BN128), so one payload needs 7 public field elements and five payloads need 27.

## Circuit

Per payload, the circuit contains:

1. **Input unpacking.** The public field elements are unpacked into boolean variables. This constrains the commitment, reference, flag, and nonce bits.
2. **Commitment.** The 440 pre-image bits and the fixed SHA-256 padding form one 512-bit block. One SHA-256 compression from the standard IV must output the commitment bits.
3. **Packing.** Each attribute's 64 pre-image bits, each 64-bit reference, and each flag byte are packed into field elements. The compared values are constrained to equal the packed pre-image attributes, so the prover cannot compare values other than the committed ones.
4. **Comparison.** A 64-bit libsnark `comparison_gadget` per attribute computes `less = a < r` and `less_or_eq = a ≤ r`.
5. **Operation constraints.** With `f` the flag of an operation:

   | Operation | Constraint |
   | --- | --- |
   | less | `f · less = f` |
   | less or equal | `f · less_or_eq = f` |
   | equal | `f · less_or_eq = f` and `f · less = 0` |
   | greater or equal | `f · (1 − less) = f` |
   | greater | `f · (1 − less_or_eq) = f` |
   | not equal | `f · (less + 1 − less_or_eq) = f` |
   | noop | none |

   The seven flag bytes of each attribute must sum to 1. Since each byte lies between 0 and 255, exactly one flag is 1.

## Cost

Measured on an Apple M1, single-threaded (`MULTICORE=OFF`), with `CURVE=ALT_BN128` and the default `RelWithDebInfo` build:

| Payloads | Constraints | Proving key | Verification key | Credential | Presentation |
| --- | --- | --- | --- | --- | --- |
| 1 | 29,746 | 25.1 MB | 2.8 kB | 285 B | 855 B |
| 2 | 59,233 | 50.1 MB | 3.6 kB | 418 B | 930 B |
| 5 | 147,694 | 125.1 MB | 6.0 kB | 817 B | 1,163 B |

| Payloads | Setup | Proving | Verification |
| --- | --- | --- | --- |
| 1 | 4.5 s | 1.5 s | 5 ms |
| 2 | 8.3 s | 2.9 s | 5 ms |
| 5 | 19.7 s | 7.5 s | 6 ms |

Constraints, proving-key size, setup time, and proving time grow linearly with the payload count, by roughly 29,500 constraints per payload. A proof is three group elements in canonical decimal encoding, about 625 bytes for any payload count. A credential takes 152 + 133·n bytes and a presentation 152 + 77·n bytes plus the proof.

`zklaim/main_benchmark.c` measures setup, proving, and verification for 1 to 20 payloads; see [Development](development.md#benchmarks).

## Design decisions

- **Setup per payload count.** The circuit contains no issuer- or credential-specific constants, so one setup serves every credential with the same payload count ([#18](https://github.com/kiliant/zklaim/issues/18)).
- **One block per pre-image.** Five 64-bit attributes plus the salt fill exactly the 55 bytes that SHA-256 pads into one block, which fixes the salt at 15 bytes ([#14](https://github.com/kiliant/zklaim/issues/14)).
- **Verifier-selected predicates.** Predicates are public inputs chosen by the verifier and are not signed, so one credential answers any request. `zklaim_ctx_verify` requires an exact match with the verifier's policy ([#7](https://github.com/kiliant/zklaim/issues/7)).
- **Nonce in the public input.** Binds each proof to one request and stops replay ([#2](https://github.com/kiliant/zklaim/issues/2)).
- **Pinned, unsigned verification key.** Verifiers pin the key per issuer and payload count, so an issuer can replace its setup without reissuing credentials.
- **Portable encodings.** Every message field has a fixed offset and byte order, and SNARK keys and proofs use one canonical decimal encoding, so all platforms produce and accept identical bytes ([#20](https://github.com/kiliant/zklaim/issues/20)).
