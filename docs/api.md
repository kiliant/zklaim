# API reference

The public API is declared in four installed headers. `<zklaim/zklaim.h>` includes the key and hash headers, so most programs include only that one.

| Header | Contents |
| --- | --- |
| `zklaim/zklaim.h` | Constants, types, contexts, setup, proofs, signing, verification, serialization |
| `zklaim/zklaim_ecc.h` | Ed25519 keys and signatures |
| `zklaim/zklaim_hash.h` | SHA-256 and hex output helpers |
| `zklaim/zklaim_wire.h` | Wire format constants and big-endian helpers |

The headers' doc comments are the authoritative per-function contracts; this page summarizes them. See the [developer guide](guide.md) for how the calls fit together.

## Conventions

- Integer results are `ZKLAIM_OK` (0) on success and nonzero on failure. Functions in `zklaim_ecc.h` and `zklaim_hash.h` return `ZKLAIM_ERROR` (1) for every failure.
- Output buffers are allocated with `malloc` and released by the caller with `free`.
- Output S-expressions are released with `gcry_sexp_release`.
- A failing `zklaim_ctx_sign`, `zklaim_proof_generate`, `zklaim_ctx_verify`, or `zklaim_ctx_deserialize` leaves the context unchanged.

## Constants

### Return codes

| Constant | Value | Meaning |
| --- | --- | --- |
| `ZKLAIM_OK` | 0 | Success |
| `ZKLAIM_ERROR` | 1 | Invalid argument, malformed input, allocation failure, or internal error |
| `ZKLAIM_INVALID_SIGNATURE` | 2 | Issuer signature does not verify |
| `ZKLAIM_INVALID_PROOF` | 3 | Proof missing or invalid for the given verification key and nonce |
| `ZKLAIM_UNTRUSTED_ISSUER` | 4 | Context names a different issuer key than the trusted one |
| `ZKLAIM_UNEXPECTED_PREDICATE` | 5 | Predicates or payload count differ from the verifier's policy |

### Sizes

| Constant | Value | Meaning |
| --- | --- | --- |
| `ZKLAIM_MAX_PAYLOAD_ATTRIBUTES` | 5 | Attributes per payload |
| `ZKLAIM_SALT_SIZE` | 15 | Salt bytes per payload |
| `ZKLAIM_PRE_SIZE` | 55 | Pre-image bytes: five 8-byte attributes and the salt |
| `ZKLAIM_NONCE_SIZE` | 32 | Verifier nonce bytes |

## Types

### `enum zklaim_op`

Comparison of an attribute with its reference value: `zklaim_less`, `zklaim_less_or_eq`, `zklaim_eq`, `zklaim_greater_or_eq`, `zklaim_greater`, `zklaim_not_eq`, and `zklaim_noop`. The enumerator values are the wire codes listed in [Concepts](concepts.md#predicates).

### `zklaim_payload`

```c
struct zklaim_payload {
    uint64_t data_ref[ZKLAIM_MAX_PAYLOAD_ATTRIBUTES];
    enum zklaim_op data_op[ZKLAIM_MAX_PAYLOAD_ATTRIBUTES];
    unsigned char salt[ZKLAIM_SALT_SIZE];
    unsigned char hash[32];
    uint8_t priv;
    unsigned char pre[ZKLAIM_PRE_SIZE];
};
```

| Field | Meaning |
| --- | --- |
| `data_ref`, `data_op` | Predicate: reference value and operation for each attribute |
| `pre` | Pre-image: five big-endian 64-bit attributes, then the salt. Access attributes with `zklaim_set_attr` and `zklaim_get_attr` |
| `salt` | Copy of the salt in `pre` |
| `hash` | SHA-256 commitment to `pre` |
| `priv` | 0 if `pre` and `salt` hold the witness, 1 if they are hidden (zeroed) |

### `zklaim_predicate`

```c
typedef struct zklaim_predicate {
    uint64_t data_ref[ZKLAIM_MAX_PAYLOAD_ATTRIBUTES];
    enum zklaim_op data_op[ZKLAIM_MAX_PAYLOAD_ATTRIBUTES];
} zklaim_predicate;
```

The verifier's references and operations for one payload. A policy is an array with one element per payload, in payload order.

### `zklaim_ctx`

```c
typedef struct zklaim_ctx {
    size_t num_of_payloads;
    zklaim_wrap_payload_ctx *pl_ctx_head;
    size_t proof_size;
    unsigned char *proof;
    unsigned char pub_key[32];
    unsigned char signature[64];
} zklaim_ctx;
```

A credential or presentation. `pl_ctx_head` points to a singly linked list of `zklaim_wrap_payload_ctx` nodes (`next`, `pl`) with `num_of_payloads` entries. `pub_key` is the issuer key recorded by `zklaim_ctx_sign` or read from a message; it is untrusted on the verifier side. `proof` holds the canonical encoding of the SNARK proof, or `NULL`.

`zklaim_sig` is declared for compatibility and unused by the API.

## Contexts and payloads

### `zklaim_context_new`

```c
zklaim_ctx *zklaim_context_new();
```

Allocates an empty context. Returns `NULL` on allocation failure.

### `zklaim_ctx_free`

```c
void zklaim_ctx_free(zklaim_ctx *ctx);
```

Frees the context, its payload list, and its proof. `NULL` is allowed.

### `zklaim_add_pl`

```c
void zklaim_add_pl(zklaim_ctx *ctx, zklaim_payload pl);
```

Appends a copy of `pl` to the context. Does not hash it.

### `zklaim_set_attr`, `zklaim_get_attr`

```c
int zklaim_set_attr(zklaim_payload *pl, uint64_t attr, uint8_t pos);
int zklaim_get_attr(const zklaim_payload *pl, uint8_t pos, uint64_t *attr);
```

Write or read attribute `pos` (0 to 4) in the payload's pre-image, in big-endian order. Return `ZKLAIM_ERROR` for an out-of-range position.

### `zklaim_hash_pl`, `zklaim_hash_ctx`

```c
void zklaim_hash_pl(zklaim_payload *pl);
void zklaim_hash_ctx(zklaim_ctx *ctx);
```

Draw a fresh random salt, store it in `pre` and `salt`, and compute the commitment `hash`, for one payload or for every payload in a context. Hashing a signed context invalidates its signature.

### `zklaim_clear_pres`

```c
void zklaim_clear_pres(zklaim_ctx *ctx);
```

Zeroes `pre` and `salt` in every payload and sets `priv` to 1. Presentations never contain witnesses, so this is memory hygiene, not a serialization requirement. A cleared context cannot generate proofs.

### `zklaim_print`

```c
void zklaim_print(zklaim_ctx *ctx);
```

Prints every payload's predicates and commitment to standard output, including attribute values and salts of payloads that are not hidden. For debugging only.

## Setup and proofs

### `zklaim_trusted_setup`

```c
int zklaim_trusted_setup(size_t num_of_payloads, unsigned char **pk, size_t *pk_size,
                         unsigned char **vk, size_t *vk_size);
```

Generates the proving and verification keys for credentials with `num_of_payloads` payloads (1 to `UINT32_MAX`). On failure, `*pk` and `*vk` are `NULL` and both sizes are zero. Whoever runs the setup can forge proofs; see [Security](security.md#trust-assumptions).

### `zklaim_proof_generate`

```c
int zklaim_proof_generate(zklaim_ctx *ctx, const unsigned char *pk, size_t pk_size,
                          const unsigned char nonce[ZKLAIM_NONCE_SIZE]);
```

Proves that the context's witnesses open its commitments and satisfy its current predicates, bound to `nonce`, and stores the proof in the context. Returns `ZKLAIM_ERROR` if an argument is `NULL`, the context has no payloads, the proving key belongs to another payload count, the witnesses do not satisfy the predicates, or proving fails.

### `zklaim_proof_verify`

```c
int zklaim_proof_verify(zklaim_ctx *ctx, const unsigned char *vk, size_t vk_size,
                        const unsigned char nonce[ZKLAIM_NONCE_SIZE]);
```

Checks only the proof against the context's own commitments and predicates. It authenticates neither the issuer nor the predicates; applications must use `zklaim_ctx_verify`.

## Signing and verification

### `zklaim_ctx_sign`

```c
int zklaim_ctx_sign(zklaim_ctx *ctx, gcry_sexp_t priv);
```

Signs the context's commitments with the Ed25519 private key `priv` and records the signature and the signer's public key in the context. The signed message is specified in the [wire format](wire-format.md#issuer-signatures-and-keys).

### `zklaim_ctx_verify`

```c
int zklaim_ctx_verify(zklaim_ctx *ctx, const unsigned char trusted_issuer_key[32],
                      const unsigned char *trusted_vk, size_t trusted_vk_size,
                      const zklaim_predicate *expected, size_t expected_count,
                      const unsigned char nonce[ZKLAIM_NONCE_SIZE]);
```

Verifies a presentation against the verifier's trust configuration and policy, in this order:

1. the context's issuer key equals `trusted_issuer_key`, else `ZKLAIM_UNTRUSTED_ISSUER`;
2. the payload count equals `expected_count` and every reference and operation equals `expected`, including `noop` slots, else `ZKLAIM_UNEXPECTED_PREDICATE`;
3. the issuer signature verifies, else `ZKLAIM_INVALID_SIGNATURE`;
4. the proof verifies for `trusted_vk` and `nonce`, else `ZKLAIM_INVALID_PROOF`.

Returns `ZKLAIM_ERROR` for `NULL` arguments, an empty policy, invalid operations in `expected`, or malformed context storage. The context is unchanged.

## Serialization

### `zklaim_ctx_serialize`

```c
size_t zklaim_ctx_serialize(zklaim_ctx *ctx, unsigned char **buf);
```

Writes a presentation: no witnesses, salts, or privacy flags, even if the context contains them. Returns the length of the new buffer, or 0 with `*buf` set to `NULL` on failure.

### `zklaim_ctx_serialize_credential`

```c
size_t zklaim_ctx_serialize_credential(zklaim_ctx *ctx, unsigned char **buf);
```

Writes a credential including the witnesses of payloads with `priv == 0`, for confidential issuer-to-prover transfer. Same conventions as `zklaim_ctx_serialize`.

### `zklaim_ctx_deserialize`

```c
int zklaim_ctx_deserialize(zklaim_ctx *ctx, unsigned char *buf, size_t len);
```

Reads a version 2 credential or presentation into an empty context. Returns `ZKLAIM_ERROR` for malformed input, an unsupported version or curve, or a context that already has payloads or a proof. The proof bytes are parsed only during verification.

## Keys and signatures (`zklaim_ecc.h`)

Keys are libgcrypt S-expressions for Ed25519 with the `eddsa` flag. Legacy ECDSA keys are rejected.

| Function | Purpose |
| --- | --- |
| `int zklaim_gen_pk(gcry_sexp_t *priv)` | Generate a private key |
| `int zklaim_get_pub(gcry_sexp_t priv, gcry_sexp_t *pub)` | Derive the public key |
| `int zklaim_pub2buf(gcry_sexp_t pub, unsigned char **buf, size_t *len)` | Encode a public key, or the public part of a private key, as 32 RFC 8032 bytes |
| `int zklaim_buf2pub(unsigned char *buf, size_t len, gcry_sexp_t *pub)` | Decode a 32-byte public key |
| `int zklaim_pk2buf(gcry_sexp_t priv, unsigned char **buf, size_t *len)` | Encode a private key as public key ‖ seed (64 bytes, secret) |
| `int zklaim_buf2pk(unsigned char *buf, size_t len, gcry_sexp_t *priv)` | Decode public key ‖ seed, checking that both agree |
| `int zklaim_sign(unsigned char *buf, size_t len, gcry_sexp_t *sig, gcry_sexp_t priv)` | Sign the exact bytes with pure Ed25519 |
| `int zklaim_verify(unsigned char *buf, size_t len, gcry_sexp_t sig, gcry_sexp_t pub)` | Verify a signature |
| `int zklaim_sig2buf(gcry_sexp_t sig, unsigned char **buf, size_t *len)` | Encode a signature as R ‖ S (64 bytes) |
| `int zklaim_buf2sig(unsigned char *buf, size_t len, gcry_sexp_t *sig)` | Decode a 64-byte signature |

Signatures and decoders enforce the RFC 8032 scalar bound S < L regardless of the installed libgcrypt version.

## Hash helpers (`zklaim_hash.h`)

| Function | Purpose |
| --- | --- |
| `int zklaim_calculate_hash(unsigned char *buf, size_t len, unsigned char **dgst)` | Allocate `*dgst` and store the 32-byte SHA-256 digest of `buf` |
| `void zklaim_print_hex(unsigned char *buf, size_t len)` | Print `buf` as hexadecimal to standard output |

## Wire helpers (`zklaim_wire.h`)

Constants for the [wire format](wire-format.md) (`ZKLAIM_WIRE_VERSION`, header and payload record sizes, message kinds), inline big-endian encoders `zklaim_store_u32`, `zklaim_load_u32`, `zklaim_store_u64`, `zklaim_load_u64`, and `zklaim_wire_curve()`, which returns the curve identifier the library was built with.
