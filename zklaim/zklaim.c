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
#include <zklaim/zklaim.h>
#include <zklaim/zklaim_ecc.h>
#include <zklaim/zklaim_hash.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

zklaim_ctx* zklaim_context_new() {
    zklaim_ctx *ctx = (zklaim_ctx*) calloc(1, sizeof(zklaim_ctx));

    return ctx;
}

void zklaim_ctx_free(zklaim_ctx *ctx) {
    // free all payloads
    zklaim_wrap_payload_ctx *back[ctx->num_of_payloads];
    zklaim_wrap_payload_ctx *cur = ctx->pl_ctx_head;
    for (size_t i=0; i<ctx->num_of_payloads; i++) {
        back[i] = cur;
        cur = cur->next;
    }

    for (int i=ctx->num_of_payloads-1; i>=0; i--) {
        free(back[i]);
    }

    // this will free if existing

    // free pk struct if existing
    if (ctx->pk_size > 0) {
        // do free
        free(ctx->pk);
    }

    // free vk struct if existing
    if(ctx->vk_size > 0) {
        // do free
        free(ctx->vk);
    }

    // free proof struct if existing
    if (ctx->proof_size > 0) {
        // do free
        free(ctx->proof);
    }

    free(ctx);
}

int zklaim_proof_generate(zklaim_ctx *ctx) {
    int res = libsnark_prove(ctx);
    return res;
}

int zklaim_proof_verify(zklaim_ctx *ctx) {
    // check if proof is present
    if (ctx->proof == NULL)
        return 1;
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
    int rand = open("/dev/urandom", O_RDONLY);
    read(rand, &pl->salt, sizeof(pl->salt));
    close(rand);
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
            printf("payload salt: %lu\n", salt);
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
void zklaim_set_attr(zklaim_payload *pl, uint64_t attr, uint8_t pos) {
    if (pos>5) {
        fprintf(stderr, "[%s (%d)] error occurred: %s\n", __FILE__, __LINE__, "zklaim only supports 5 attribute slots per payload");

        return;
    }
    memcpy((pl->pre + pos*8), &attr, 8);
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

void plain_ctx(zklaim_ctx *ctx, unsigned char **buf, size_t *total_length) {
    size_t tl;
    // lay out structure in buffer
    tl = ctx->num_of_payloads * sizeof(((zklaim_payload*)0)->hash);
    tl += ctx->vk_size;
    *buf = (unsigned char*) calloc(1, tl);

    // serialize payloads
    zklaim_wrap_payload_ctx *cur = ctx->pl_ctx_head;
    for (size_t i=0; i<ctx->num_of_payloads; i++) {
        memcpy(*buf+i*sizeof(((zklaim_payload*)0)->hash), cur->pl.hash, sizeof(((zklaim_payload*)0)->hash));
        cur = cur->next;
    }

    // serialize verification key
    memcpy(*buf + ctx->num_of_payloads * sizeof(((zklaim_payload*)0)->hash), ctx->vk, ctx->vk_size);

    *total_length = tl;
}

int zklaim_ctx_verify(zklaim_ctx *ctx) {
    // verify signature
    gcry_sexp_t sig, pub;
    size_t total_length;
    unsigned char *buf;

    if (zklaim_buf2sig(ctx->signature, sizeof(ctx->signature), &sig)) {
        fprintf(stderr, "[%s (%d)] error occurred: %s\n", __FILE__, __LINE__, "could not load sig");
        return ZKLAIM_ERROR;
    }

    if (zklaim_buf2pub(ctx->pub_key, sizeof(ctx->pub_key), &pub)) {
        fprintf(stderr, "[%s (%d)] error occurred: %s\n", __FILE__, __LINE__, "could not load pub");
        return ZKLAIM_ERROR;
    }

    plain_ctx(ctx, &buf, &total_length);

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
    int res = 0;
    // TODO: insert
    unsigned char *buf;
    size_t total_length;

    plain_ctx(ctx, &buf, &total_length);

    // sign the buffer and return res
    gcry_sexp_t sig;

    //unsigned char *md;
    //zklaim_calculate_hash(buf, total_length, &md);
    //printf("-> signing hash (%zu): ", total_length);
    //print_hex(md, 32);
    //printf("\n------\n");
    //print_hex(buf, total_length);
    //free(md);
    //printf("\n");

    zklaim_sign(buf, total_length, &sig, priv);

    size_t sigsize;
    unsigned char* sigbuf;
    zklaim_sig2buf(sig, &sigbuf, &sigsize);

    if (sigsize != sizeof(ctx->signature)) {
        gcry_sexp_release(sig);
        return 1;
    }

    memcpy(ctx->signature, sigbuf, sizeof(ctx->signature));

    gcry_sexp_release(sig);

    free(sigbuf);

    free(buf);
    return res;
}

int zklaim_ctx_deserialize(zklaim_ctx *ctx, unsigned char *buf, size_t len) {
    // 0 - extract zklaim header and set counts and sizes
    unsigned char *buf_iterator = buf;
    size_t total_length, num_of_payloads;
    unsigned char header_integrity[256];
    // first, verify hash of header to ensure integrity
    SHA256(buf, sizeof(zklaim_header)-sizeof(((zklaim_header*)0)->hash), header_integrity);
    if (!memcmp(header_integrity, buf+16, 32)) {
        fprintf(stderr, "[%s (%d)] error occurred: %s\n", __FILE__, __LINE__, "zklaim_header integrity check failed");
        return ZKLAIM_ERROR;
    }

    zklaim_header *header = (zklaim_header*) buf_iterator;

    num_of_payloads = ntohl(header->num_of_payloads);
    //printf("pl %d\n", num_of_payloads);
    ctx->vk_size = ntohl(header->size_of_vk);
    //printf("vk %d\n", size_of_vk);
    ctx->proof_size = ntohl(header->size_of_proof);
    //printf("proof %d\n", size_of_proof);

    memcpy(ctx->pub_key, header->pub_key, sizeof(ctx->pub_key));

    total_length = sizeof(zklaim_header);
    total_length += num_of_payloads * sizeof(zklaim_payload);
    total_length += ctx->vk_size;
    total_length += sizeof(((zklaim_ctx*)0)->signature);
    total_length += ctx->proof_size;

    if (len != total_length) {
        fprintf(stderr, "[%s (%d)] error occurred: %s\n", __FILE__, __LINE__, "buffer containing zklaim_ctx has invalid total_length");
        //printf("buffer containing zklaim_ctx has invalid length (len: %zu vs total: %zu)\n", len, total_length);
        return ZKLAIM_ERROR;
    }

    // now point on first payload
    buf_iterator = buf + sizeof(zklaim_header);

    // 1 - deserialized payloads
    for (uint32_t i=0; i<num_of_payloads; i++) {
        zklaim_payload *pl = (zklaim_payload*) buf_iterator;
        zklaim_add_pl(ctx, pl[i]);
    }

    buf_iterator = buf + sizeof(zklaim_header) + ctx->num_of_payloads * sizeof(zklaim_payload);

    // 2 - deserialize verification key
    ctx->vk = (unsigned char*) malloc(ctx->vk_size);
    memcpy(ctx->vk, buf+sizeof(zklaim_header) + ctx->num_of_payloads*sizeof(zklaim_payload), ctx->vk_size);

    buf_iterator = buf+sizeof(zklaim_header) + ctx->num_of_payloads*sizeof(zklaim_payload) + ctx->vk_size;

    // 3 - deserialize signature
    memcpy(ctx->signature, buf_iterator, sizeof((zklaim_ctx*)0)->signature);
    buf_iterator += sizeof((zklaim_ctx*)0)->signature;

    // 4- deserialize proof
    //printf("%d\n", size_of_proof);
    if (ctx->proof_size > 0) {
    ctx->proof = (unsigned char*) malloc(ctx->proof_size);
    memcpy(ctx->proof, buf+sizeof(zklaim_header) + ctx->num_of_payloads*sizeof(zklaim_payload) + ctx->vk_size + sizeof(((zklaim_ctx*)0)->signature), ctx->proof_size);
    }

    //return zklaim_ctx_verify(ctx);
    return ZKLAIM_OK;
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
    SHA256((unsigned char*)header, sizeof(zklaim_header)-32, header->hash);

    // 3 - serialize payloads
    zklaim_payload *pl = (zklaim_payload*) (*buf+sizeof(zklaim_header));
    zklaim_wrap_payload_ctx *cur = ctx->pl_ctx_head;
    for (size_t i=0; i<ctx->num_of_payloads; i++) {
        pl[i] = cur->pl;
        cur = cur->next;
    }

    // 4 - serialize verification key
    memcpy(*buf+sizeof(zklaim_header) + ctx->num_of_payloads*sizeof(zklaim_payload), ctx->vk, ctx->vk_size);

    // 5 - serialize signature
    memcpy(*buf+sizeof(zklaim_header) + ctx->num_of_payloads*sizeof(zklaim_payload) + ctx->vk_size, ctx->signature, sizeof(((zklaim_ctx*)0)->signature));

    // 6 - serialize proof
    memcpy(*buf+sizeof(zklaim_header) + ctx->num_of_payloads*sizeof(zklaim_payload) + ctx->vk_size + sizeof(((zklaim_ctx*)0)->signature), ctx->proof, ctx->proof_size);

    return total_length;
}

// test method for wrapping a c++ function in c
int zklaim_test() {
    return 0;
    //return libsnark_verify();
}

#endif
