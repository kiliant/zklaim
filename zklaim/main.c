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
 * Test File for zklaim c implementation
 */

#include <zklaim/zklaim.h>
#include <zklaim/zklaim_ecc.h>
#include <zklaim/zklaim_hash.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gcrypt.h>

// to boost up valgrind
int worker() {
    gcry_sexp_t priv, pub;
    zklaim_gen_pk(&priv);
    zklaim_get_pub(priv, &pub);
    unsigned char *pubbuf;
    size_t publen;
    zklaim_pub2buf(pub, &pubbuf, &publen);

    printf("===========================================================================\n");
    printf("===========================================================================\n");
    printf("============================== ISSUER =====================================\n");
    printf("===========================================================================\n");
    printf("===========================================================================\n");
    //zklaim_ctx* ctx = zklaim_context_init();
    //zklaim_proving_key* pk = zklaim_proving_key_get(ctx);
    /*
     * - 1 -
     * initialize data structures
     */
    printf("[ISSUER] initializing context\n");
    zklaim_ctx *ctx = zklaim_context_new();

    if (sizeof(ctx->pub_key) != publen) {
        printf("size mismatch!");
        return 1;
    }

    // TODO: there should be a zklaim method for this
    memcpy(ctx->pub_key, pubbuf, sizeof(ctx->pub_key));
    // The verifier obtains this key from its issuer configuration, separately
    // from the prover's serialized context. This demo uses the issuer above.
    unsigned char trusted_issuer_key[32];
    memcpy(trusted_issuer_key, pubbuf, sizeof(trusted_issuer_key));
    free(pubbuf);

    // Verifier policy: prove that attribute 0 is at least 20. The verifier
    // supplies this request to the prover and retains its own copy.
    const zklaim_predicate expected[] = {
        {{20, 0, 0, 0, 0},
         {zklaim_greater_or_eq, zklaim_noop, zklaim_noop, zklaim_noop, zklaim_noop}}
    };

    /*
     * - 2 -
     * setup the first payload
     */
    printf("[ISSUER] Setting up payloads..\n");
    zklaim_payload pl, pl2;
    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data_ref[0] = 18;
    pl.data_op[0] = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data_ref[1] = 1;
    pl.data_op[1] = zklaim_eq;
    pl.data_ref[2] = 2;
    pl.data_op[2] = zklaim_eq;
    pl.data_ref[3] = 3;
    pl.data_op[3] = zklaim_eq;
    pl.data_ref[4] = 600;
    pl.data_op[4] = zklaim_less;
    pl.priv = 0;

    zklaim_predicate issued_predicate;
    memcpy(issued_predicate.data_ref, pl.data_ref, sizeof(pl.data_ref));
    memcpy(issued_predicate.data_op, pl.data_op, sizeof(pl.data_op));

    memset(&pl2, 0, sizeof(zklaim_payload));
    pl2.data_ref[0] = 0;
    pl2.data_op[0] = zklaim_noop;
    pl2.data_ref[1] = 0;
    pl2.data_op[1] = zklaim_noop;
    pl2.data_ref[2] = 0;
    pl2.data_op[2] = zklaim_noop;
    pl2.data_ref[3] = 0;
    pl2.data_op[3] = zklaim_noop;
    pl2.data_ref[4] = 9223372036854775807;
    pl2.data_op[4] = zklaim_less_or_eq;
    pl2.priv = 0;

    // fill in the values
    zklaim_set_attr(&pl, 23, 0);
    zklaim_set_attr(&pl, 1, 1);
    zklaim_set_attr(&pl, 2, 2);
    zklaim_set_attr(&pl, 3, 3);
    zklaim_set_attr(&pl, 599, 4);

    zklaim_set_attr(&pl2, 0, 0);
    zklaim_set_attr(&pl2, 0, 1);
    zklaim_set_attr(&pl2, 0, 2);
    zklaim_set_attr(&pl2, 0, 3);
    zklaim_set_attr(&pl2, 9223372036854775807, 4);

    /*
     * - 3 -
     * add payload to context
     */
    printf("[ISSUER] adding payloads to context\n");
    zklaim_add_pl(ctx, pl);
    /* zklaim_add_pl(ctx, pl); */
    //zklaim_add_pl(ctx, pl2);
    zklaim_hash_ctx(ctx);

    // The circuit depends only on the payload count: an issuer runs the setup
    // once per supported count and reuses the keys for every credential.
    // Provers receive the proving key; verifiers pin the verification key.
    unsigned char *pk = NULL, *vk = NULL;
    size_t pk_size = 0, vk_size = 0;
    printf("[ISSUER] performing trusted setup for %zu-payload credentials\n", ctx->num_of_payloads);
    printf("-> trusted setup result: %s\n",
           (zklaim_trusted_setup(ctx->num_of_payloads, &pk, &pk_size, &vk, &vk_size) ? "failed" : "passed"));

    //unsigned char* buf;
    //size_t vksize = zklaim_verification_key_serialize(ctx, &buf);
    //printf("serialized vk size: %zuB\n", vksize);

    // write key to disk
    //FILE* f = fopen("/tmp/vk1", "w");
    //fwrite(buf, vksize, 1, f);
    //fclose(f);

    //zklaim_verification_key_deserialize(ctx2, buf, vksize);

    //free(buf);

    //size_t pksize = zklaim_proving_key_serialize(ctx, &buf);
    //printf("serialized pk size: %.2fMB\n", ((float) pksize)/1000/1000);

    //zklaim_proving_key_deserialize(ctx, buf, pksize);

    //zklaim_print(ctx);

    //zklaim_ctx_sign(ctx, priv);


    printf("-> signing context: %s\n", zklaim_ctx_sign(ctx, priv) ? "failed" : "passed");

    unsigned char* ctx_issuer;

    printf("\n[ISSUER] serializing context\n");
    size_t len = zklaim_ctx_serialize_credential(ctx, &ctx_issuer);

    /*
     * - 4 -
     * generate proof
     */

    //printf("\n-> signing context: %s\n", zklaim_ctx_sign(ctx, priv) ? "failed" : "passed");

    //unsigned char* proof;
    //size_t proof_size = zklaim_proof_serialize(ctx, &proof);
    //printf("serialized proof size: %zuB\n", proof_size);

    //zklaim_proof* zkproof_imported;

    //zklaim_proof_deserialize(ctx, proof, proof_size);

    printf("===========================================================================\n");
    printf("===========================================================================\n");
    printf("============================== PROVER =====================================\n");
    printf("===========================================================================\n");
    printf("===========================================================================\n");


    zklaim_ctx* ctx_prover = zklaim_context_new();
    printf("\n[PROVER] deserializing context\n");
    printf("-> deserialisation status: %s\n\n", zklaim_ctx_deserialize(ctx_prover, ctx_issuer, len) ? "failed" : "passed");

    zklaim_print(ctx_prover);

    // The verifier sends a fresh challenge with its predicate request, so a
    // presentation it receives cannot be replayed to anyone else.
    unsigned char nonce[ZKLAIM_NONCE_SIZE];
    gcry_randomize(nonce, sizeof(nonce), GCRY_STRONG_RANDOM);

    int res = zklaim_ctx_verify(ctx_prover, trusted_issuer_key, vk, vk_size, &issued_predicate, 1, nonce);
    printf("[PROVER] verification result: %d %s\n", res, (res ? "failed" : "passed"));
    printf("                              ^--- failure with code 3 (ZKLAIM_INVALID_PROOF) is ok for the prover, as signature passes, but (non-existing) proof fails\n\n");

    printf("[PROVER] applying the verifier's requested predicate\n");
    printf("[PROVER] generating proof\n");

    memcpy(ctx_prover->pl_ctx_head->pl.data_ref, expected[0].data_ref, sizeof(expected[0].data_ref));
    memcpy(ctx_prover->pl_ctx_head->pl.data_op, expected[0].data_op, sizeof(expected[0].data_op));

    zklaim_print(ctx_prover);

    printf("-> proof generation status: %s\n\n",
           (zklaim_proof_generate(ctx_prover, pk, pk_size, nonce) ? "failed" : "passed"));


    printf("[PROVER] blinding attributes\n");
    zklaim_clear_pres(ctx_prover);


    printf("[PROVER] serializing context\n\n");

    unsigned char *ctx_prover_buf;
    len = zklaim_ctx_serialize(ctx_prover, &ctx_prover_buf);

    /*
     * - 5 -
     * verify proof
     */
    printf("===========================================================================\n");
    printf("===========================================================================\n");
    printf("============================= VERIFIER ====================================\n");
    printf("===========================================================================\n");
    printf("===========================================================================\n");

    zklaim_ctx* ctx_verifier = zklaim_context_new();
    printf("\n[VERIFIER] deserializing context\n");
    printf("-> deserialisation status: %s\n\n", zklaim_ctx_deserialize(ctx_verifier, ctx_prover_buf, len) ? "failed" : "passed");
    printf("[VERIFIER] verifying proof and context\n");
    res = zklaim_ctx_verify(ctx_verifier, trusted_issuer_key, vk, vk_size, expected,
                            sizeof(expected) / sizeof(expected[0]), nonce);
    printf("verification result: %d %s\n\n", res, (res ? "failed" : "passed"));

    zklaim_print(ctx_verifier);

    free(ctx_prover_buf);
    free(ctx_issuer);
    free(pk);
    free(vk);
    zklaim_ctx_free(ctx);
    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    zklaim_ctx_free(ctx_prover);
    zklaim_ctx_free(ctx_verifier);

    return res;
}

int main() {
    return worker();
}
