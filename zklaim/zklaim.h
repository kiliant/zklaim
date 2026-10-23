/*
 * This file is part of zklaim.
 * zklaim is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * zklaim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with zklaim. If not, see https://www.gnu.org/licenses/.
 */

/*
 * Forward Declarations and Definitions of Datatypes used in zklaim
 */

/**
 * @file zklaim.h
 * @brief Main Header File of zklaim
 * @author Thomas Kilian
 */

#ifndef ZKLAIM_H
#define ZKLAIM_H

#include <zklaim/zklaim_ecc.h>
#include <zklaim/zklaim_export.h>
#include <stdint.h>
#include <stdlib.h>

#define ZKLAIM_OK 0
#define ZKLAIM_ERROR 1
#define ZKLAIM_INVALID_SIGNATURE 2
#define ZKLAIM_INVALID_PROOF 3
#define ZKLAIM_UNTRUSTED_ISSUER 4
#define ZKLAIM_UNEXPECTED_PREDICATE 5
#define ZKLAIM_MAX_PAYLOAD_ATTRIBUTES 5
// A 15-byte salt is the largest that keeps the five attributes and the salt
// in one SHA-256 block (55 bytes plus padding), i.e. one in-circuit compression.
#define ZKLAIM_SALT_SIZE 15
#define ZKLAIM_PRE_SIZE (ZKLAIM_MAX_PAYLOAD_ATTRIBUTES * 8 + ZKLAIM_SALT_SIZE)
#define ZKLAIM_NONCE_SIZE 32

// enum specifying the operations of zklaim comparisons
enum zklaim_op {
    zklaim_less = 1,
    zklaim_less_or_eq = 3,
    zklaim_eq = 2,
    zklaim_greater_or_eq = 10,
    zklaim_greater = 8,
    zklaim_not_eq = 9,
    zklaim_noop = 99
};

// fd
typedef struct zklaim_wrap_payload_ctx zklaim_wrap_payload_ctx;
typedef struct zklaim_ctx zklaim_ctx;
typedef struct zklaim_payload zklaim_payload;

struct zklaim_payload {
    uint64_t data_ref[ZKLAIM_MAX_PAYLOAD_ATTRIBUTES];
    enum zklaim_op data_op[ZKLAIM_MAX_PAYLOAD_ATTRIBUTES];
    unsigned char salt[ZKLAIM_SALT_SIZE];
    unsigned char hash[32];
    uint8_t priv;
    unsigned char pre[ZKLAIM_PRE_SIZE]; // five big-endian uint64 attributes, then the salt
};

/** Verifier-selected references and operations for one payload, in wire order. */
typedef struct zklaim_predicate {
    uint64_t data_ref[ZKLAIM_MAX_PAYLOAD_ATTRIBUTES];
    enum zklaim_op data_op[ZKLAIM_MAX_PAYLOAD_ATTRIBUTES];
} zklaim_predicate;

typedef struct zklaim_wrap_payload_ctx {
    zklaim_wrap_payload_ctx *next;
    zklaim_payload pl;
} zklaim_wrap_payload_ctx;

typedef struct zklaim_sig {
    int size;
    unsigned char *sig;
} zklaim_sig;

/**
 * maintaining the state
 * TODO
 */
typedef struct zklaim_ctx {
    size_t num_of_payloads;
    zklaim_wrap_payload_ctx *pl_ctx_head;
    size_t proof_size;
    unsigned char *proof;
    unsigned char pub_key[32];
    unsigned char signature[64];
} zklaim_ctx;


/**
 * bootstrapping
 * called by issuer/prover
 * sets up the circuits
 *
 * @return newly created zklaim context datastructure
 */
ZKLAIM_API zklaim_ctx* zklaim_context_new();


/**
 * frees a given zklaim context
 *
 * @param ctx context to free; NULL is allowed
 */
ZKLAIM_API void zklaim_ctx_free(zklaim_ctx *ctx);


/**
 * serialize a presentation into a versioned, portable buffer
 * the buffer of appropriate size is created by the callee
 * Pre-images, salt, and privacy flags are never included, even if ctx still
 * contains witnesses. Use zklaim_ctx_serialize_credential for issuer-to-prover
 * witness transfer. Legacy unversioned buffers are not supported.
 *
 * @param ctx the context to serialize
 * @param buf the buffer containing the serialized context
 * @return size of the created buffer in bytes, or zero on invalid input or
 *         allocation failure; *buf is NULL on failure
 */
ZKLAIM_API size_t zklaim_ctx_serialize(zklaim_ctx *ctx, unsigned char **buf);

/**
 * Serialize a credential WITH its private witnesses for issuer-to-prover
 * transfer over a confidential channel. Never use this for presentations.
 * The allocation and return conventions match zklaim_ctx_serialize.
 */
ZKLAIM_API size_t zklaim_ctx_serialize_credential(zklaim_ctx *ctx, unsigned char **buf);


/**
 * deserialize a versioned credential or presentation into a context
 *
 * @param ctx empty context where to store the deserialization result
 * @param buf the buffer containing the context data
 * @param len length of the buffer in bytes
 * @return ZKLAIM_OK on success, or ZKLAIM_ERROR for invalid input,
 *         allocation failure, or a context with payloads or proof storage.
 *         On failure, the destination context is unchanged. Proof contents
 *         are parsed when verifying.
 */
ZKLAIM_API int zklaim_ctx_deserialize(zklaim_ctx *ctx, unsigned char *buf, size_t len);


/**
 * verifies a context against the verifier's trusted issuer, verification key,
 * predicates, and challenge
 *
 * @param ctx the context to verify
 * @param trusted_issuer_key trusted 32-byte issuer public key, obtained separately
 *        from the received context (the encoding returned by zklaim_pub2buf)
 * @param trusted_vk verification key pinned for this issuer and payload count,
 *        as returned by zklaim_trusted_setup and obtained separately
 * @param trusted_vk_size length of trusted_vk in bytes
 * @param expected verifier-selected predicates, one per payload in payload order;
 *        all references and operations must match exactly, including noop slots
 * @param expected_count number of predicates; must be nonzero and match the
 *        context's payload count and list length
 * @param nonce the fresh challenge this verifier sent to the prover; never
 *        reuse a nonce, or a previously seen presentation can be replayed
 * @return ZKLAIM_OK only if the issuer, predicates, signature, and proof pass;
 *         ZKLAIM_UNTRUSTED_ISSUER for a different embedded issuer key;
 *         ZKLAIM_UNEXPECTED_PREDICATE for a different predicate or payload count;
 *         ZKLAIM_INVALID_SIGNATURE or ZKLAIM_INVALID_PROOF for cryptographic failure,
 *         including a proof for another nonce or verification key;
 *         ZKLAIM_ERROR for NULL arguments, invalid expected operations, an empty
 *         policy, malformed context storage, or an internal error.
 *
 * Do not obtain any trust argument from the untrusted context. The context is
 * unchanged.
 */
ZKLAIM_API int zklaim_ctx_verify(zklaim_ctx *ctx, const unsigned char trusted_issuer_key[32],
                      const unsigned char *trusted_vk, size_t trusted_vk_size,
                      const zklaim_predicate *expected, size_t expected_count,
                      const unsigned char nonce[ZKLAIM_NONCE_SIZE]);


/**
 * signs a context
 * this means that the hashes contained in the context will be signed, and the
 * signer's public key is stored as the context's issuer key
 *
 * @param ctx the context to sign
 * @param priv the private key used for creating the signature
 * @return ZKLAIM_OK on success, or ZKLAIM_ERROR if signing or serialization fails.
 *         On failure, the existing context signature and issuer key are unchanged.
 */
ZKLAIM_API int zklaim_ctx_sign(zklaim_ctx*, gcry_sexp_t);


/**
 * generate a proof for the given context, bound to the verifier's challenge
 *
 * @param ctx the context for which the proof should be generated
 * @param pk proving key from zklaim_trusted_setup for the context's payload count
 * @param pk_size length of pk in bytes
 * @param nonce the challenge received from the verifier
 * @return ZKLAIM_OK on success, or ZKLAIM_ERROR if an argument is NULL, the
 *         context has no payloads, the proving key belongs to another circuit,
 *         or proof generation fails. On failure, the context is unchanged.
 */
ZKLAIM_API int zklaim_proof_generate(zklaim_ctx *ctx, const unsigned char *pk, size_t pk_size,
                          const unsigned char nonce[ZKLAIM_NONCE_SIZE]);


/**
 * verifies only the proof contained in the given context
 *
 * This low-level check uses the context's predicates. It does not authenticate
 * the issuer or enforce verifier policy; applications accepting credentials
 * must use zklaim_ctx_verify instead.
 *
 * @param ctx the context to verify
 * @param vk verification key for the context's payload count
 * @param vk_size length of vk in bytes
 * @param nonce the challenge the proof must be bound to
 * @result ZKLAIM_OK on success
 */
ZKLAIM_API int zklaim_proof_verify(zklaim_ctx *ctx, const unsigned char *vk, size_t vk_size,
                        const unsigned char nonce[ZKLAIM_NONCE_SIZE]);


/**
 * perform the trusted setup for credentials with a given number of payloads
 *
 * The circuit depends only on the payload count, so an issuer runs this once
 * per supported count and reuses the keys for every credential. Provers need
 * the proving key; verifiers pin the verification key. Whoever runs the setup
 * can forge proofs for its circuit, so verifiers must trust that party (for an
 * issuer-run setup, the issuer).
 *
 * @param num_of_payloads number of payloads per credential, 1 to UINT32_MAX
 * @param pk receives the newly allocated proving key
 * @param pk_size receives the length of the proving key in bytes
 * @param vk receives the newly allocated verification key
 * @param vk_size receives the length of the verification key in bytes
 * @return ZKLAIM_OK on success, or ZKLAIM_ERROR for invalid arguments or if
 *         setup fails. On failure, *pk and *vk are NULL and both sizes are zero.
 */
ZKLAIM_API int zklaim_trusted_setup(size_t num_of_payloads, unsigned char **pk, size_t *pk_size,
                         unsigned char **vk, size_t *vk_size);


/**
 * add a payload to a given context
 *
 * @param ctx the context to add the payload to
 * @param pl the payload to add
 * @return ZKLAIM_OK on success
 */
ZKLAIM_API void zklaim_add_pl(zklaim_ctx *ctx, zklaim_payload pl);


/**
 * hash a single payload
 *
 * @param pl the payload to hash
 */
ZKLAIM_API void zklaim_hash_pl(zklaim_payload *pl);


/**
 * hash a context
 * this creates hashes for every payload contained in the context
 * this also ensures that a fresh salt is generated for every payload
 *
 * @param ctx the context to hash
 */
ZKLAIM_API void zklaim_hash_ctx(zklaim_ctx *ctx);


/**
 * prints information about a given ctx
 *
 * @param ctx the context to print
 */
ZKLAIM_API void zklaim_print(zklaim_ctx *ctx);


/**
 * sets an attribute in a given payload
 * the following values for param pos are supported
 * 0: set attribute #1
 * 1: set attribute #2
 * 2: set attribute #3
 * 3: set attribute #4
 * 4: set attribute #5
 *
 * @param pl the payload in which an attribute shall be set
 * @param attr the value of the attribute to set
 * @param pos the position of the attribute within the payload (0-4)
 * @return ZKLAIM_OK on success, or ZKLAIM_ERROR if pos is out of range.
 *         An invalid position leaves the payload unchanged.
 */
ZKLAIM_API int zklaim_set_attr(zklaim_payload *pl, uint64_t attr, uint8_t pos);

/** Read an attribute from the canonical big-endian pre-image. */
ZKLAIM_API int zklaim_get_attr(const zklaim_payload *pl, uint8_t pos, uint64_t *attr);


/**
 * clears the pre-images and salts from a given context
 *
 * @param ctx the context to clear
 */
ZKLAIM_API void zklaim_clear_pres(zklaim_ctx *ctx);

#endif // ZKLAIM_H
