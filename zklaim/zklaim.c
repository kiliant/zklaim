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

/**
 * zklaim implementation
 */
#ifndef ZKLAIM_C
#define ZKLAIM_C

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <zklaim/zklaim.h>
#include <zklaim/zklaim_ecc.h>
#include <zklaim/zklaim_hash.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <zklaim/zklaim_wire.h>

unsigned char zklaim_wire_curve(void) {
#if defined(CURVE_ALT_BN128)
    return 1;
#elif defined(CURVE_BN128)
    return 2;
#elif defined(CURVE_EDWARDS)
    return 3;
#elif defined(CURVE_MNT4)
    return 4;
#elif defined(CURVE_MNT6)
    return 5;
#else
    return 0;
#endif
}

zklaim_ctx* zklaim_context_new() {
    zklaim_ctx *ctx = (zklaim_ctx*) calloc(1, sizeof(zklaim_ctx));

    return ctx;
}

void zklaim_ctx_free(zklaim_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }

    zklaim_wrap_payload_ctx *cur = ctx->pl_ctx_head;
    while (cur != NULL) {
        zklaim_wrap_payload_ctx *next = cur->next;
        free(cur);
        cur = next;
    }

    free(ctx->pk);
    free(ctx->vk);
    free(ctx->proof);
    free(ctx);
}

int zklaim_proof_generate(zklaim_ctx *ctx) {
    int res = libsnark_prove(ctx);
    return res;
}

int zklaim_proof_verify(zklaim_ctx *ctx) {
    // check if proof is present
    if (ctx == NULL || ctx->proof == NULL)
        return ZKLAIM_ERROR;
    return libsnark_verify(ctx);
}

int zklaim_trusted_setup(zklaim_ctx *ctx) {
    return libsnark_trusted_setup(ctx);
}

void zklaim_add_pl(zklaim_ctx *ctx, zklaim_payload pl) {
    zklaim_wrap_payload_ctx *cur = ctx->pl_ctx_head;
    zklaim_wrap_payload_ctx *n = (zklaim_wrap_payload_ctx*) calloc(1, sizeof(zklaim_wrap_payload_ctx));

    // this adds salt and hashes
    //zklaim_hash_pl(&pl);

    // traverse until we reach end of list
    if (cur != NULL) {
        while (cur->next != NULL) {
            cur = cur->next;
        }
        cur->next = n;
        n->pl = pl;
    } else {
        n->pl = pl;
        ctx->pl_ctx_head = n;
    }
    ctx->num_of_payloads += 1;
}

void zklaim_hash_pl(zklaim_payload *pl) {
    gcry_randomize(&pl->salt, sizeof(pl->salt), GCRY_STRONG_RANDOM);
    // copy over salt to pre
    zklaim_store_u64(pl->pre + 5 * sizeof(uint64_t), pl->salt);
    SHA256((unsigned char*) pl->pre, sizeof(pl->pre), pl->hash);
}

void zklaim_hash_ctx(zklaim_ctx *ctx) {
    zklaim_wrap_payload_ctx *cur = ctx->pl_ctx_head;
    while (cur != NULL) {
        zklaim_hash_pl(&cur->pl);
        // TODO: maybe clear pres
        cur = cur->next;
    }
}

const char* zklaim_parse_op (enum zklaim_op e) {
    // TODO: see compilation warning
    switch (e) {
        case zklaim_noop:
            return "noop";
        case zklaim_less:
            return "<";
        case zklaim_less_or_eq:
            return "<=";
        case zklaim_eq:
            return "=";
        case zklaim_greater_or_eq:
            return ">=";
        case zklaim_greater:
            return ">";
        case zklaim_not_eq:
            return "!=";
        default:
            return "enum zklaim_op: no valid value";
    }
}

// prints information about a given context
void zklaim_print(zklaim_ctx *ctx){
    // primarily print payloads!
    zklaim_wrap_payload_ctx *cur = ctx->pl_ctx_head;
    size_t counter = 0;
    uint64_t data[ZKLAIM_MAX_PAYLOAD_ATTRIBUTES];
    uint64_t salt;
    int i;
    while (cur != NULL) {
        // recover data
        for (uint8_t pos = 0; pos < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; ++pos) {
            zklaim_get_attr(&cur->pl, pos, &data[pos]);
        }
        salt = zklaim_load_u64(cur->pl.pre + 40);
        printf("======================================================================\n");
        printf("=======          viewing information about payload #%zu          =======\n", counter);
        printf("======================================================================\n");
        printf("Format: [actual] op reference\n");
        if (cur->pl.priv != 1) {
            for (int i = 0; i < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; i++)
                printf("data%i: [%"PRIu64"] %s %"PRIu64"\n", i, data[i], zklaim_parse_op(cur->pl.data_op[i]), cur->pl.data_ref[i]);
            printf("payload salt: %"PRIu64"\n", salt);
        } else {
            for (int i = 0; i < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; i++)
                printf("data%i: [hidden] %s %"PRIu64"\n", i, zklaim_parse_op(cur->pl.data_op[i]), cur->pl.data_ref[i]);
            printf("payload salt: [hidden]\n");
        }
        printf("Hash: ");
        zklaim_print_hex(cur->pl.hash, 32);
        printf("\n");
        printf("======================================================================\n\n");
        cur = cur->next;
        counter++;
    }
}

// set attribute at given position within pl
int zklaim_set_attr(zklaim_payload *pl, uint64_t attr, uint8_t pos) {
    if (pl == NULL || pos >= ZKLAIM_MAX_PAYLOAD_ATTRIBUTES) {
        fprintf(stderr, "[%s (%d)] error occurred: %s\n", __FILE__, __LINE__, "attribute position is out of range");

        return ZKLAIM_ERROR;
    }
    zklaim_store_u64(pl->pre + pos * 8, attr);
    return ZKLAIM_OK;
}

int zklaim_get_attr(const zklaim_payload *pl, uint8_t pos, uint64_t *attr) {
    if (pl == NULL || attr == NULL || pos >= ZKLAIM_MAX_PAYLOAD_ATTRIBUTES) return ZKLAIM_ERROR;
    *attr = zklaim_load_u64(pl->pre + pos * 8);
    return ZKLAIM_OK;
}

// clears all pre-images in the context
void zklaim_clear_pres(zklaim_ctx *ctx) {
    zklaim_wrap_payload_ctx *cur = ctx->pl_ctx_head;
    while (cur != NULL) {
        memset(cur->pl.pre, 0, sizeof(cur->pl.pre));
        memset(&cur->pl.salt, 0, sizeof(cur->pl.salt));
        cur->pl.priv = 1;
        cur = cur->next;
    }
}

static int plain_ctx(zklaim_ctx *ctx, unsigned char **buf, size_t *total_length) {
    *buf = NULL;
    *total_length = 0;
    if (ctx->num_of_payloads > UINT32_MAX || ctx->vk_size > UINT32_MAX ||
        ctx->vk_size > SIZE_MAX - 16 || (ctx->vk_size > 0 && ctx->vk == NULL) ||
        ctx->num_of_payloads > (SIZE_MAX - 16 - ctx->vk_size) / 32) return ZKLAIM_ERROR;
    const size_t len = 16 + ctx->num_of_payloads * 32 + ctx->vk_size;
    unsigned char *encoded = calloc(1, len);
    if (encoded == NULL) return ZKLAIM_ERROR;
    // Domain, version, algorithm, curve and explicit lengths bind the signature
    // to this protocol, without fixing the prover's selectable predicates.
    memcpy(encoded, "ZKSG", 4);
    encoded[5] = ZKLAIM_WIRE_VERSION;
    encoded[6] = 1; // RFC 8032 Ed25519
    encoded[7] = zklaim_wire_curve();
    zklaim_store_u32(encoded + 8, (uint32_t) ctx->num_of_payloads);
    zklaim_store_u32(encoded + 12, (uint32_t) ctx->vk_size);
    const zklaim_wrap_payload_ctx *node = ctx->pl_ctx_head;
    for (size_t i = 0; i < ctx->num_of_payloads; ++i) {
        if (node == NULL) { free(encoded); return ZKLAIM_ERROR; }
        memcpy(encoded + 16 + i * 32, node->pl.hash, 32);
        node = node->next;
    }
    if (node != NULL) { free(encoded); return ZKLAIM_ERROR; }
    if (ctx->vk_size > 0) memcpy(encoded + 16 + ctx->num_of_payloads * 32, ctx->vk, ctx->vk_size);
    *buf = encoded;
    *total_length = len;
    return ZKLAIM_OK;
}

int zklaim_ctx_verify(zklaim_ctx *ctx, const unsigned char trusted_issuer_key[32],
                      const zklaim_predicate *expected, size_t expected_count) {
    if (ctx == NULL || trusted_issuer_key == NULL || expected == NULL ||
        expected_count == 0 || expected_count > SIZE_MAX / sizeof(*expected) ||
        (ctx->vk_size > 0 && ctx->vk == NULL) ||
        ctx->num_of_payloads > (SIZE_MAX - ctx->vk_size) / sizeof(((zklaim_payload*)0)->hash)) {
        return ZKLAIM_ERROR;
    }

    unsigned char issuer_key[sizeof(ctx->pub_key)];
    memcpy(issuer_key, trusted_issuer_key, sizeof(issuer_key));
    if (memcmp(ctx->pub_key, issuer_key, sizeof(issuer_key)) != 0) {
        return ZKLAIM_UNTRUSTED_ISSUER;
    }
    if (ctx->num_of_payloads != expected_count) {
        return ZKLAIM_UNEXPECTED_PREDICATE;
    }
    const zklaim_wrap_payload_ctx *cur = ctx->pl_ctx_head;
    for (size_t i = 0; i < expected_count; ++i) {
        if (cur == NULL) {
            return ZKLAIM_ERROR;
        }
        for (size_t attr = 0; attr < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; ++attr) {
            switch (expected[i].data_op[attr]) {
                case zklaim_less:
                case zklaim_less_or_eq:
                case zklaim_eq:
                case zklaim_greater_or_eq:
                case zklaim_greater:
                case zklaim_not_eq:
                case zklaim_noop:
                    break;
                default:
                    return ZKLAIM_ERROR;
            }
            if (cur->pl.data_ref[attr] != expected[i].data_ref[attr] ||
                cur->pl.data_op[attr] != expected[i].data_op[attr]) {
                return ZKLAIM_UNEXPECTED_PREDICATE;
            }
        }
        cur = cur->next;
    }
    if (cur != NULL) {
        return ZKLAIM_ERROR;
    }

    // verify signature
    gcry_sexp_t sig, pub;
    size_t total_length;
    unsigned char *buf;

    if (zklaim_buf2sig(ctx->signature, sizeof(ctx->signature), &sig)) {
        fprintf(stderr, "[%s (%d)] error occurred: %s\n", __FILE__, __LINE__, "could not load sig");
        return ZKLAIM_ERROR;
    }

    if (zklaim_buf2pub(issuer_key, sizeof(issuer_key), &pub)) {
        fprintf(stderr, "[%s (%d)] error occurred: %s\n", __FILE__, __LINE__, "could not load pub");
        gcry_sexp_release(sig);
        return ZKLAIM_ERROR;
    }

    if (plain_ctx(ctx, &buf, &total_length) != ZKLAIM_OK) {
        gcry_sexp_release(pub);
        gcry_sexp_release(sig);
        return ZKLAIM_ERROR;
    }

    //unsigned char *md;
    //zklaim_calculate_hash(buf, total_length, &md);
    //printf("-> verifying hash (%zu): ", total_length);
    //print_hex(md, 32);
    //printf("\n------\n");
    //print_hex(buf, total_length);
    //free(md);
    //printf("\n");

    if (zklaim_verify(buf, total_length, sig, pub)) {
        free(buf);
        gcry_sexp_release(pub);
        gcry_sexp_release(sig);

        return ZKLAIM_INVALID_SIGNATURE;
    }

    // verify libsnark proof if present
    if (zklaim_proof_verify(ctx)) {
        free(buf);
        gcry_sexp_release(pub);
        gcry_sexp_release(sig);

        return ZKLAIM_INVALID_PROOF;
    }

    gcry_sexp_release(pub);
    gcry_sexp_release(sig);
    free(buf);

    return ZKLAIM_OK;
}

int zklaim_ctx_sign(zklaim_ctx *ctx, gcry_sexp_t priv) {
    int res = ZKLAIM_ERROR;
    unsigned char *buf = NULL;
    unsigned char *sigbuf = NULL;
    size_t total_length = 0;
    size_t sigsize = 0;
    gcry_sexp_t sig = NULL;

    if (ctx == NULL || priv == NULL) {
        return ZKLAIM_ERROR;
    }
    if (plain_ctx(ctx, &buf, &total_length) != ZKLAIM_OK ||
        zklaim_sign(buf, total_length, &sig, priv) != ZKLAIM_OK ||
        zklaim_sig2buf(sig, &sigbuf, &sigsize) != ZKLAIM_OK ||
        sigbuf == NULL || sigsize != sizeof(ctx->signature)) {
        goto cleanup;
    }

    memcpy(ctx->signature, sigbuf, sizeof(ctx->signature));
    res = ZKLAIM_OK;

cleanup:
    gcry_sexp_release(sig);
    free(sigbuf);
    free(buf);
    return res;
}

static int valid_wire_op(unsigned char op) {
    switch (op) {
        case zklaim_less: case zklaim_less_or_eq: case zklaim_eq:
        case zklaim_greater_or_eq: case zklaim_greater: case zklaim_not_eq:
        case zklaim_noop: return 1;
        default: return 0;
    }
}

int zklaim_ctx_deserialize(zklaim_ctx *ctx, unsigned char *buf, size_t len) {
    if (ctx == NULL || buf == NULL || len < ZKLAIM_WIRE_HEADER_SIZE ||
        ctx->num_of_payloads != 0 || ctx->pl_ctx_head != NULL ||
        ctx->pk_size != 0 || ctx->pk != NULL || ctx->vk_size != 0 || ctx->vk != NULL ||
        ctx->proof_size != 0 || ctx->proof != NULL) return ZKLAIM_ERROR;
    // No struct casts: every field has a specified offset and byte order.
    if (memcmp(buf, "ZKLM", 4) != 0 || buf[4] != 0 || buf[5] != ZKLAIM_WIRE_VERSION ||
        (buf[6] != ZKLAIM_WIRE_CREDENTIAL && buf[6] != ZKLAIM_WIRE_PRESENTATION) ||
        buf[7] != zklaim_wire_curve() || zklaim_load_u32(buf + 20) != 0) return ZKLAIM_ERROR;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(buf, 56, digest);
    if (memcmp(digest, buf + 56, sizeof(digest)) != 0) return ZKLAIM_ERROR;
    const int credential = buf[6] == ZKLAIM_WIRE_CREDENTIAL;
    const size_t payload_size = credential ? ZKLAIM_WIRE_CREDENTIAL_PAYLOAD_SIZE : ZKLAIM_WIRE_PUBLIC_PAYLOAD_SIZE;
    const size_t count = zklaim_load_u32(buf + 8);
    const size_t vk_size = zklaim_load_u32(buf + 12);
    const size_t proof_size = zklaim_load_u32(buf + 16);
    size_t remaining = len - ZKLAIM_WIRE_HEADER_SIZE;
    if (count > remaining / payload_size) return ZKLAIM_ERROR;
    remaining -= count * payload_size;
    if (vk_size > remaining) return ZKLAIM_ERROR;
    remaining -= vk_size;
    if (sizeof(ctx->signature) > remaining) return ZKLAIM_ERROR;
    remaining -= sizeof(ctx->signature);
    if (proof_size != remaining) return ZKLAIM_ERROR;

    zklaim_ctx *parsed = zklaim_context_new();
    if (parsed == NULL) return ZKLAIM_ERROR;
    const unsigned char *cursor = buf + ZKLAIM_WIRE_HEADER_SIZE;
    zklaim_wrap_payload_ctx **tail = &parsed->pl_ctx_head;
    for (size_t i = 0; i < count; ++i, cursor += payload_size) {
        zklaim_wrap_payload_ctx *node = calloc(1, sizeof(*node));
        if (node == NULL) goto failure;
        *tail = node;
        tail = &node->next;
        for (size_t attr = 0; attr < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; ++attr) {
            node->pl.data_ref[attr] = zklaim_load_u64(cursor + attr * 8);
            if (!valid_wire_op(cursor[40 + attr])) goto failure;
            node->pl.data_op[attr] = (enum zklaim_op) cursor[40 + attr];
        }
        memcpy(node->pl.hash, cursor + 45, 32);
        node->pl.priv = 1;
        if (credential) {
            if (cursor[77] > 1) goto failure;
            node->pl.priv = cursor[77];
            if (node->pl.priv == 1) {
                for (size_t j = 0; j < 48; ++j) if (cursor[78 + j] != 0) goto failure;
            } else {
                memcpy(node->pl.pre, cursor + 78, 48);
                node->pl.salt = zklaim_load_u64(node->pl.pre + 40);
            }
        }
    }
    parsed->num_of_payloads = count;
    if (vk_size > 0) {
        parsed->vk = malloc(vk_size);
        if (parsed->vk == NULL) goto failure;
        memcpy(parsed->vk, cursor, vk_size);
    }
    parsed->vk_size = vk_size;
    cursor += vk_size;
    memcpy(parsed->signature, cursor, sizeof(parsed->signature));
    cursor += sizeof(parsed->signature);
    if (proof_size > 0) {
        parsed->proof = malloc(proof_size);
        if (parsed->proof == NULL) goto failure;
        memcpy(parsed->proof, cursor, proof_size);
    }
    parsed->proof_size = proof_size;
    memcpy(parsed->pub_key, buf + 24, sizeof(parsed->pub_key));
    *ctx = *parsed;
    free(parsed);
    return ZKLAIM_OK;
failure:
    zklaim_ctx_free(parsed);
    return ZKLAIM_ERROR;
}

static size_t serialize_context(zklaim_ctx *ctx, unsigned char **buf, int credential) {
    if (buf == NULL) return 0;
    *buf = NULL;
    if (ctx == NULL || ctx->num_of_payloads > UINT32_MAX || ctx->vk_size > UINT32_MAX ||
        ctx->proof_size > UINT32_MAX || (ctx->vk_size > 0 && ctx->vk == NULL) ||
        (ctx->proof_size > 0 && ctx->proof == NULL)) return 0;
    const size_t payload_size = credential ? ZKLAIM_WIRE_CREDENTIAL_PAYLOAD_SIZE : ZKLAIM_WIRE_PUBLIC_PAYLOAD_SIZE;
    size_t total = ZKLAIM_WIRE_HEADER_SIZE + sizeof(ctx->signature);
    if (ctx->vk_size > SIZE_MAX - total) return 0;
    total += ctx->vk_size;
    if (ctx->proof_size > SIZE_MAX - total) return 0;
    total += ctx->proof_size;
    if (ctx->num_of_payloads > (SIZE_MAX - total) / payload_size) return 0;
    total += ctx->num_of_payloads * payload_size;
    const zklaim_wrap_payload_ctx *check = ctx->pl_ctx_head;
    for (size_t i = 0; i < ctx->num_of_payloads; ++i) {
        if (check == NULL) return 0;
        check = check->next;
    }
    if (check != NULL) return 0;
    unsigned char *encoded = calloc(1, total);
    if (encoded == NULL) return 0;
    memcpy(encoded, "ZKLM", 4);
    encoded[5] = ZKLAIM_WIRE_VERSION;
    encoded[6] = credential ? ZKLAIM_WIRE_CREDENTIAL : ZKLAIM_WIRE_PRESENTATION;
    encoded[7] = zklaim_wire_curve();
    zklaim_store_u32(encoded + 8, (uint32_t) ctx->num_of_payloads);
    zklaim_store_u32(encoded + 12, (uint32_t) ctx->vk_size);
    zklaim_store_u32(encoded + 16, (uint32_t) ctx->proof_size);
    memcpy(encoded + 24, ctx->pub_key, 32);
    SHA256(encoded, 56, encoded + 56);
    unsigned char *cursor = encoded + ZKLAIM_WIRE_HEADER_SIZE;
    const zklaim_wrap_payload_ctx *node = ctx->pl_ctx_head;
    for (size_t i = 0; i < ctx->num_of_payloads; ++i, cursor += payload_size) {
        if (node == NULL) goto failure;
        for (size_t attr = 0; attr < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; ++attr) {
            if (!valid_wire_op((unsigned char) node->pl.data_op[attr]) ||
                node->pl.data_op[attr] > UINT8_MAX || node->pl.data_op[attr] < 0) goto failure;
            zklaim_store_u64(cursor + attr * 8, node->pl.data_ref[attr]);
            cursor[40 + attr] = (unsigned char) node->pl.data_op[attr];
        }
        memcpy(cursor + 45, node->pl.hash, 32);
        if (credential) {
            if (node->pl.priv > 1) goto failure;
            cursor[77] = node->pl.priv;
            if (node->pl.priv == 0) memcpy(cursor + 78, node->pl.pre, 48);
        }
        node = node->next;
    }
    if (node != NULL) goto failure;
    if (ctx->vk_size > 0) memcpy(cursor, ctx->vk, ctx->vk_size);
    cursor += ctx->vk_size;
    memcpy(cursor, ctx->signature, sizeof(ctx->signature));
    cursor += sizeof(ctx->signature);
    if (ctx->proof_size > 0) memcpy(cursor, ctx->proof, ctx->proof_size);
    *buf = encoded;
    return total;
failure:
    free(encoded);
    return 0;
}

size_t zklaim_ctx_serialize(zklaim_ctx *ctx, unsigned char **buf) {
    return serialize_context(ctx, buf, 0);
}

size_t zklaim_ctx_serialize_credential(zklaim_ctx *ctx, unsigned char **buf) {
    return serialize_context(ctx, buf, 1);
}

// test method for wrapping a c++ function in c
int zklaim_test() {
    return 0;
    //return libsnark_verify();
}

#endif
