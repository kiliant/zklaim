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
#include <stdint.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define ZKLAIM_OK 0
#define ZKLAIM_ERROR 1
#define ZKLAIM_INVALID_SIGNATURE 2
#define ZKLAIM_INVALID_PROOF 3
#define ZKLAIM_UNTRUSTED_ISSUER 4
#define ZKLAIM_UNEXPECTED_PREDICATE 5
#define ZKLAIM_MAX_PAYLOAD_ATTRIBUTES 5

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
typedef struct zklaim_proving_key zklaim_proving_key;
typedef struct zklaim_verification_key zklaim_verification_key;
typedef struct zklaim_payload zklaim_payload;
typedef struct zklaim_proof zklaim_proof;
typedef struct zklaim_header zklaim_header;

struct zklaim_payload {
    uint64_t data_ref[ZKLAIM_MAX_PAYLOAD_ATTRIBUTES];
    enum zklaim_op data_op[ZKLAIM_MAX_PAYLOAD_ATTRIBUTES];
    uint64_t salt;
    unsigned char hash[32];
    uint8_t priv;
    unsigned char pre[48]; // this is by definition set to 0 if public
};

/** Verifier-selected references and operations for one payload, in wire order. */
typedef struct zklaim_predicate {
    uint64_t data_ref[ZKLAIM_MAX_PAYLOAD_ATTRIBUTES];
    enum zklaim_op data_op[ZKLAIM_MAX_PAYLOAD_ATTRIBUTES];
} zklaim_predicate;

struct zklaim_header {
    uint32_t num_of_payloads;
    uint32_t size_of_vk;
    uint32_t size_of_sig;
    uint32_t size_of_proof;
    unsigned char pub_key[32];
    unsigned char hash[32];
};

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
    size_t pk_size;
    unsigned char *pk;
    size_t vk_size;
    unsigned char *vk;
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
zklaim_ctx* zklaim_context_new();


/**
 * frees a given zklaim context
 *
 * @param ctx context to free; NULL is allowed
 */
void zklaim_ctx_free(zklaim_ctx *ctx);


/**
 * serialize context into a buffer
 * the buffer of appropriate size is created by the callee
 *
 * @param ctx the context to serialize
 * @param buf the buffer containing the serialized context
 * @return size of the created buffer in bytes
 */
size_t zklaim_ctx_serialize(zklaim_ctx *ctx, unsigned char **buf);


/**
 * deserialize a given buffer into a context
 *
 * @param ctx empty context where to store the deserialization result
 * @param buf the buffer containing the context data
 * @param len length of the buffer in bytes
 * @return ZKLAIM_OK on success, or ZKLAIM_ERROR for invalid input,
 *         allocation failure, or a context with payloads or key/proof storage.
 *         On failure, the destination context is unchanged. Key and proof
 *         contents are parsed when generating or verifying a proof.
 */
int zklaim_ctx_deserialize(zklaim_ctx *ctx, unsigned char *buf, size_t len);


/**
 * verifies a context against the verifier's trusted issuer and predicates
 *
 * @param ctx the context to verify
 * @param trusted_issuer_key trusted 32-byte issuer public key, obtained separately
 *        from the received context (the encoding returned by zklaim_pub2buf)
 * @param expected verifier-selected predicates, one per payload in payload order;
 *        all references and operations must match exactly, including noop slots
 * @param expected_count number of predicates; must be nonzero and match the
 *        context's payload count and list length
 * @return ZKLAIM_OK only if the issuer, predicates, signature, and proof pass;
 *         ZKLAIM_UNTRUSTED_ISSUER for a different embedded issuer key;
 *         ZKLAIM_UNEXPECTED_PREDICATE for a different predicate or payload count;
 *         ZKLAIM_INVALID_SIGNATURE or ZKLAIM_INVALID_PROOF for cryptographic failure;
 *         ZKLAIM_ERROR for NULL arguments, invalid expected operations, an empty
 *         policy, malformed context storage, or an internal error.
 *
 * This replaces the former one-argument API. Do not obtain trusted_issuer_key
 * or expected from the untrusted context. The context is unchanged.
 */
int zklaim_ctx_verify(zklaim_ctx *ctx, const unsigned char trusted_issuer_key[32],
                      const zklaim_predicate *expected, size_t expected_count);


/**
 * signs a context
 * this means that the hashes contained in the context will be signed
 *
 * @param ctx the context to sign
 * @param priv the private key used for creating the signature
 * @return ZKLAIM_OK on success, or ZKLAIM_ERROR if signing or serialization fails.
 *         On failure, the existing context signature is unchanged.
 */
int zklaim_ctx_sign(zklaim_ctx*, gcry_sexp_t);


/**
 * generate a proof for the given context
 *
 * @param ctx the context for which the proof should be generated
 * @return ZKLAIM_OK on success, or ZKLAIM_ERROR if the context is NULL,
 *         has no payloads, or proof generation fails.
 */
int zklaim_proof_generate(zklaim_ctx *ctx);


/**
 * verifies only the proof contained in the given context
 *
 * This low-level check uses the context's verification key and predicates. It
 * does not authenticate the issuer or enforce verifier policy; applications
 * accepting credentials must use zklaim_ctx_verify instead.
 *
 * @param ctx the context to verify
 * @result ZKLAIM_OK on success
 */
int zklaim_proof_verify(zklaim_ctx *ctx);


/**
 * perform the trusted setup for a given context
 *
 * @param ctx the context for which to generate the keys
 * @return ZKLAIM_OK on success, or ZKLAIM_ERROR if the context is NULL
 *         or has no payloads, or setup fails.
 */
int zklaim_trusted_setup(zklaim_ctx *ctx);


/**
 * add a payload to a given context
 *
 * @param ctx the context to add the payload to
 * @param pl the payload to add
 * @return ZKLAIM_OK on success
 */
void zklaim_add_pl(zklaim_ctx *ctx, zklaim_payload pl);


/**
 * hash a single payload
 *
 * @param pl the payload to hash
 */
void zklaim_hash_pl(zklaim_payload *pl);


/**
 * hash a context
 * this creates hashes for every payload contained in the context
 * this also ensures that a fresh salt is generated for every payload
 *
 * @param ctx the context to hash
 */
void zklaim_hash_ctx(zklaim_ctx *ctx);


/**
 * prints information about a given ctx
 *
 * @param ctx the context to print
 */
void zklaim_print(zklaim_ctx *ctx);


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
int zklaim_set_attr(zklaim_payload *pl, uint64_t attr, uint8_t pos);


/**
 * clears the pre-images and salts from a given context
 *
 * @param ctx the context to clear
 */
void zklaim_clear_pres(zklaim_ctx *ctx);

// forward declarations of C++ wrappers imported via linkage
int libsnark_trusted_setup(zklaim_ctx*);
int libsnark_prove(zklaim_ctx*);
int libsnark_verify(zklaim_ctx*);
int libsnark_import_proof(zklaim_proof**, unsigned char*, size_t);
size_t libsnark_export_proof(zklaim_proof*, unsigned char**);
void libsnark_free(zklaim_proving_key*, zklaim_verification_key*, zklaim_proof*);
int zklaim_test();

#endif // ZKLAIM_H
