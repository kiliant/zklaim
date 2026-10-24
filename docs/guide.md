# Developer guide

This guide walks through issuing a credential, requesting a predicate, proving it, and verifying the presentation. It assumes the [concepts](concepts.md). The snippets combine into one program; [`zklaim/main.c`](../zklaim/main.c) and [`zklaim/tests/wire_portability.cpp`](../zklaim/tests/wire_portability.cpp) are complete examples in the repository.

## Setup

Install the library as described in [Building](building.md#install-and-link), include `<zklaim/zklaim.h>`, and link with `-lzklaim -lgcrypt`.

zklaim uses libgcrypt for randomness, hashing, and signatures but does not initialize it. Initialize libgcrypt once at startup, before the first zklaim call:

```c
#include <zklaim/zklaim.h>
#include <gcrypt.h>

if (!gcry_check_version(GCRYPT_VERSION)) { /* handle error */ }
```

All parties must use libraries built with the same `CURVE` option; messages record the curve, and a library built for another curve rejects them.

### Conventions

- Functions return `ZKLAIM_OK` (0) on success. The [API reference](api.md#return-codes) lists the error codes.
- Functions that return a buffer allocate it with `malloc`; the caller releases it with `free`. Contexts are released with `zklaim_ctx_free`, libgcrypt S-expressions with `gcry_sexp_release`.
- `zklaim_ctx` is a plain structure. Its payloads form a singly linked list starting at `pl_ctx_head`; applications walk it to read or set predicates.

## Issuer

### Keys

The issuer generates an Ed25519 key once and publishes its 32-byte public key:

```c
gcry_sexp_t issuer_key;
if (zklaim_gen_pk(&issuer_key) != ZKLAIM_OK) { /* handle error */ }

unsigned char *issuer_pub;
size_t issuer_pub_len;
if (zklaim_pub2buf(issuer_key, &issuer_pub, &issuer_pub_len) != ZKLAIM_OK) { /* handle error */ }
```

`zklaim_pk2buf` stores the private key as 64 bytes (public key followed by the RFC 8032 seed), and `zklaim_buf2pk` loads it again. That buffer is secret.

### Trusted setup

The issuer runs the setup once for each payload count it supports. Setup takes a few seconds per payload.

```c
unsigned char *pk, *vk;
size_t pk_size, vk_size;
if (zklaim_trusted_setup(1, &pk, &pk_size, &vk, &vk_size) != ZKLAIM_OK) { /* handle error */ }
```

The proving key `pk` goes to provers. Verifiers receive `vk` together with `issuer_pub` through a trusted channel and pin both.

### Issuing a credential

Fill in the attributes with `zklaim_set_attr`, add the payload, hash, sign, and serialize:

```c
static size_t issue_credential(gcry_sexp_t issuer_key, unsigned char **credential) {
    *credential = NULL;
    zklaim_payload pl;
    memset(&pl, 0, sizeof(pl));
    for (uint8_t i = 0; i < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; ++i) {
        pl.data_op[i] = zklaim_noop;   // predicates are chosen later by verifiers
    }
    zklaim_set_attr(&pl, 19900514, 0); // date of birth as YYYYMMDD
    zklaim_set_attr(&pl, 276, 1);      // country code

    zklaim_ctx *ctx = zklaim_context_new();
    if (ctx == NULL) return 0;
    if (zklaim_add_pl(ctx, pl) != ZKLAIM_OK) {
        zklaim_ctx_free(ctx);
        return 0;
    }
    zklaim_hash_ctx(ctx);              // fresh salts and commitments
    size_t len = 0;
    if (zklaim_ctx_sign(ctx, issuer_key) == ZKLAIM_OK) {
        len = zklaim_ctx_serialize_credential(ctx, credential);
    }
    zklaim_ctx_free(ctx);
    return len;
}
```

The order matters:

- `zklaim_add_pl` copies the payload. Set attributes before adding it, or change the copy through `ctx->pl_ctx_head`.
- `zklaim_hash_ctx` draws fresh salts for every payload. Call it once, after the last attribute change and before signing. Hashing again after signing changes the commitments, and verification then fails with `ZKLAIM_INVALID_SIGNATURE`.
- Use `zklaim_set_attr` and `zklaim_get_attr` for attribute values. They write the big-endian encoding the commitment and circuit expect; copying native integers into `pre` does not.

The credential contains the attribute values and salts. Send it only over a confidential channel.

## Verifier: request

The verifier defines its policy as one predicate per payload and sends it to the prover with a fresh random nonce:

```c
const zklaim_predicate policy[] = {
    {{20080101, 276, 0, 0, 0},
     {zklaim_less, zklaim_eq, zklaim_noop, zklaim_noop, zklaim_noop}}
};
const size_t policy_count = sizeof(policy) / sizeof(policy[0]);

unsigned char nonce[ZKLAIM_NONCE_SIZE];
gcry_randomize(nonce, sizeof(nonce), GCRY_STRONG_RANDOM);
```

This policy requires a date of birth before 2008-01-01 and country code 276. The verifier keeps its own copy of the policy and the nonce for verification and never reuses a nonce.

## Prover

The prover loads the credential, replaces the issued predicates with the verifier's request, proves, and serializes the presentation:

```c
static size_t present(const unsigned char *credential, size_t credential_len,
                      const zklaim_predicate *request, size_t request_count,
                      const unsigned char nonce[ZKLAIM_NONCE_SIZE],
                      const unsigned char *pk, size_t pk_size,
                      unsigned char **presentation) {
    *presentation = NULL;
    zklaim_ctx *ctx = zklaim_context_new();
    if (ctx == NULL) return 0;
    size_t len = 0;
    if (zklaim_ctx_deserialize(ctx, (unsigned char *) credential, credential_len) != ZKLAIM_OK ||
        ctx->num_of_payloads != request_count) {
        goto done;
    }
    size_t i = 0;
    for (zklaim_wrap_payload_ctx *cur = ctx->pl_ctx_head; cur != NULL; cur = cur->next, ++i) {
        memcpy(cur->pl.data_ref, request[i].data_ref, sizeof(cur->pl.data_ref));
        memcpy(cur->pl.data_op, request[i].data_op, sizeof(cur->pl.data_op));
    }
    if (zklaim_proof_generate(ctx, pk, pk_size, nonce) != ZKLAIM_OK) {
        goto done;                     // the attributes do not satisfy the request
    }
    zklaim_clear_pres(ctx);            // optional: drop witnesses from memory
    len = zklaim_ctx_serialize(ctx, presentation);
done:
    zklaim_ctx_free(ctx);
    return len;
}
```

`zklaim_proof_generate` returns `ZKLAIM_ERROR` if the attributes do not satisfy the request. `zklaim_ctx_serialize` never writes witnesses; `zklaim_clear_pres` only removes them from memory.

To check the issuer's signature on a fresh credential, the prover can call `zklaim_ctx_verify` with the issued predicates. Without a proof it returns `ZKLAIM_INVALID_PROOF` when the signature is valid and `ZKLAIM_INVALID_SIGNATURE` when it is not.

## Verifier: verification

The verifier deserializes the presentation and verifies it against its trusted keys, its own policy, and the nonce it sent:

```c
static int accept(const unsigned char *presentation, size_t len,
                  const unsigned char trusted_issuer_key[32],
                  const unsigned char *trusted_vk, size_t trusted_vk_size,
                  const zklaim_predicate *policy, size_t policy_count,
                  const unsigned char nonce[ZKLAIM_NONCE_SIZE]) {
    zklaim_ctx *received = zklaim_context_new();
    if (received == NULL) return ZKLAIM_ERROR;
    int res = zklaim_ctx_deserialize(received, (unsigned char *) presentation, len);
    if (res == ZKLAIM_OK) {
        res = zklaim_ctx_verify(received, trusted_issuer_key, trusted_vk, trusted_vk_size,
                                policy, policy_count, nonce);
    }
    zklaim_ctx_free(received);
    return res;
}
```

Accept the presentation only if the result is `ZKLAIM_OK`:

| Result | Meaning |
| --- | --- |
| `ZKLAIM_OK` | Trusted issuer, exact policy, valid signature, valid proof for this nonce |
| `ZKLAIM_UNTRUSTED_ISSUER` | The presentation names a different issuer key |
| `ZKLAIM_UNEXPECTED_PREDICATE` | A reference, operation, or the payload count differs from the policy |
| `ZKLAIM_INVALID_SIGNATURE` | The issuer signature does not match the commitments |
| `ZKLAIM_INVALID_PROOF` | The proof is missing or invalid, or was made for another nonce or verification key |
| `ZKLAIM_ERROR` | Malformed input, invalid arguments, or an internal error |

Never take the issuer key, verification key, or predicates from the received context, and never call `zklaim_proof_verify` instead: it checks only the proof and does not authenticate the issuer or enforce the policy.

## Common mistakes

- Reusing a nonce, or deriving it from predictable data. Each request needs `ZKLAIM_NONCE_SIZE` fresh random bytes.
- Building the expected predicates by copying the received presentation. The verification then accepts whatever the prover chose.
- Calling `zklaim_hash_ctx` after `zklaim_ctx_sign`.
- Passing a non-empty context to `zklaim_ctx_deserialize`. It requires a fresh context from `zklaim_context_new`.
- Calling `zklaim_print` on a context with witnesses in production code: it prints attribute values and salts to standard output.
