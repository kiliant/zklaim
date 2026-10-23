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
#include <arpa/inet.h>

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
    memcpy((pl->pre + 5*sizeof(uint64_t)), &pl->salt, sizeof(uint64_t));
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
        memcpy(&data[0], cur->pl.pre, 8);
        memcpy(&data[1], cur->pl.pre+8, 8);
        memcpy(&data[2], cur->pl.pre+16, 8);
        memcpy(&data[3], cur->pl.pre+24, 8);
        memcpy(&data[4], cur->pl.pre+32, 8);
        memcpy(&salt, cur->pl.pre+40, 8);
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
    if (pos >= ZKLAIM_MAX_PAYLOAD_ATTRIBUTES) {
        fprintf(stderr, "[%s (%d)] error occurred: %s\n", __FILE__, __LINE__, "attribute position is out of range");

        return ZKLAIM_ERROR;
    }
    memcpy((pl->pre + pos*8), &attr, 8);
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

int plain_ctx(zklaim_ctx *ctx, unsigned char **buf, size_t *total_length) {
    size_t tl;
    // lay out structure in buffer
    tl = ctx->num_of_payloads * sizeof(((zklaim_payload*)0)->hash);
    tl += ctx->vk_size;
    *total_length = 0;
    *buf = (unsigned char*) calloc(1, tl ? tl : 1);
    if (*buf == NULL) {
        return ZKLAIM_ERROR;
    }

    // serialize payloads
    zklaim_wrap_payload_ctx *cur = ctx->pl_ctx_head;
    for (size_t i=0; i<ctx->num_of_payloads; i++) {
        memcpy(*buf+i*sizeof(((zklaim_payload*)0)->hash), cur->pl.hash, sizeof(((zklaim_payload*)0)->hash));
        cur = cur->next;
    }

    // serialize verification key
    if (ctx->vk_size > 0) {
        memcpy(*buf + ctx->num_of_payloads * sizeof(((zklaim_payload*)0)->hash), ctx->vk, ctx->vk_size);
    }

    *total_length = tl;
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

int zklaim_ctx_deserialize(zklaim_ctx *ctx, unsigned char *buf, size_t len) {
    if (ctx == NULL || buf == NULL || len < sizeof(zklaim_header)) {
        return ZKLAIM_ERROR;
    }
    // Import into an empty context so existing storage is never lost or appended.
    if (ctx->num_of_payloads != 0 || ctx->pl_ctx_head != NULL ||
        ctx->pk_size != 0 || ctx->pk != NULL ||
        ctx->vk_size != 0 || ctx->vk != NULL ||
        ctx->proof_size != 0 || ctx->proof != NULL) {
        return ZKLAIM_ERROR;
    }

    // The caller's buffer need not be aligned for either serialized structure.
    zklaim_header header;
    memcpy(&header, buf, sizeof(header));
    unsigned char header_integrity[SHA256_DIGEST_LENGTH];
    SHA256(buf, offsetof(zklaim_header, hash), header_integrity);
    if (memcmp(header_integrity, header.hash, sizeof(header.hash)) != 0) {
        return ZKLAIM_ERROR;
    }

    const size_t num_of_payloads = ntohl(header.num_of_payloads);
    const size_t vk_size = ntohl(header.size_of_vk);
    const size_t proof_size = ntohl(header.size_of_proof);
    if (ntohl(header.size_of_sig) != sizeof(ctx->signature)) {
        return ZKLAIM_ERROR;
    }

    // Subtract each section from the supplied length. Check before multiplying
    // or subtracting, so even UINT32_MAX sizes cannot wrap on 32-bit platforms.
    size_t remaining = len - sizeof(header);
    if (num_of_payloads > remaining / sizeof(zklaim_payload)) {
        return ZKLAIM_ERROR;
    }
    remaining -= num_of_payloads * sizeof(zklaim_payload);
    if (vk_size > remaining) {
        return ZKLAIM_ERROR;
    }
    remaining -= vk_size;
    if (sizeof(ctx->signature) > remaining) {
        return ZKLAIM_ERROR;
    }
    remaining -= sizeof(ctx->signature);
    if (proof_size != remaining) {
        return ZKLAIM_ERROR;
    }

    // Commit only after every allocation and copy succeeds.
    zklaim_ctx *parsed = zklaim_context_new();
    if (parsed == NULL) {
        return ZKLAIM_ERROR;
    }
    const unsigned char *cursor = buf + sizeof(header);
    zklaim_wrap_payload_ctx **tail = &parsed->pl_ctx_head;
    for (size_t i = 0; i < num_of_payloads; ++i) {
        zklaim_wrap_payload_ctx *node = calloc(1, sizeof(*node));
        if (node == NULL) {
            goto failure;
        }
        memcpy(&node->pl, cursor, sizeof(node->pl));
        cursor += sizeof(node->pl);
        *tail = node;
        tail = &node->next;
    }
    parsed->num_of_payloads = num_of_payloads;
    if (vk_size > 0) {
        parsed->vk = malloc(vk_size);
        if (parsed->vk == NULL) {
            goto failure;
        }
        memcpy(parsed->vk, cursor, vk_size);
    }
    parsed->vk_size = vk_size;
    cursor += vk_size;
    memcpy(parsed->signature, cursor, sizeof(parsed->signature));
    cursor += sizeof(parsed->signature);
    if (proof_size > 0) {
        parsed->proof = malloc(proof_size);
        if (parsed->proof == NULL) {
            goto failure;
        }
        memcpy(parsed->proof, cursor, proof_size);
    }
    parsed->proof_size = proof_size;
    memcpy(parsed->pub_key, header.pub_key, sizeof(parsed->pub_key));
    *ctx = *parsed;
    free(parsed);
    return ZKLAIM_OK;

failure:
    zklaim_ctx_free(parsed);
    return ZKLAIM_ERROR;
}

size_t zklaim_ctx_serialize(zklaim_ctx *ctx, unsigned char **buf) {
    // 1 - build zklaim_header
    size_t total_length;

    total_length = sizeof(zklaim_header);
    total_length += ctx->num_of_payloads * sizeof(zklaim_payload);
    total_length += ctx->vk_size + ctx->proof_size;
    total_length += sizeof(((zklaim_ctx*)0)->signature);

    // 2 - allocate buf of appropriate size
    *buf = (unsigned char*) calloc(1, total_length);
    if (*buf == NULL) {
        fprintf(stderr, "[%s (%d)] error occurred: %s\n", __FILE__, __LINE__, "could not allocate");
        return 0;
    }

    // 3 - fill in header
    zklaim_header *header = (zklaim_header*) *buf;
    header->num_of_payloads = htonl(ctx->num_of_payloads);
    header->size_of_vk = htonl(ctx->vk_size);
    header->size_of_sig = htonl(sizeof(((zklaim_ctx*)0)->signature));
    header->size_of_proof = htonl(ctx->proof_size);
    memcpy(header->pub_key, ctx->pub_key, sizeof(header->pub_key));
    // hash header values
    SHA256((unsigned char*)header, offsetof(zklaim_header, hash), header->hash);

    // 3 - serialize payloads
    zklaim_payload *pl = (zklaim_payload*) (*buf+sizeof(zklaim_header));
    zklaim_wrap_payload_ctx *cur = ctx->pl_ctx_head;
    for (size_t i=0; i<ctx->num_of_payloads; i++) {
        pl[i] = cur->pl;
        cur = cur->next;
    }

    // 4 - serialize verification key
    if (ctx->vk_size > 0) {
        memcpy(*buf+sizeof(zklaim_header) + ctx->num_of_payloads*sizeof(zklaim_payload), ctx->vk, ctx->vk_size);
    }

    // 5 - serialize signature
    memcpy(*buf+sizeof(zklaim_header) + ctx->num_of_payloads*sizeof(zklaim_payload) + ctx->vk_size, ctx->signature, sizeof(((zklaim_ctx*)0)->signature));

    // 6 - serialize proof
    if (ctx->proof_size > 0) {
        memcpy(*buf+sizeof(zklaim_header) + ctx->num_of_payloads*sizeof(zklaim_payload) + ctx->vk_size + sizeof(((zklaim_ctx*)0)->signature), ctx->proof, ctx->proof_size);
    }

    return total_length;
}

// test method for wrapping a c++ function in c
int zklaim_test() {
    return 0;
    //return libsnark_verify();
}

#endif
