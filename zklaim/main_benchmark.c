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
#include <pthread.h>
#include <time.h>

static pthread_mutex_t file_lock = PTHREAD_MUTEX_INITIALIZER;

// to boost up valgrind
int worker(int k) {
    if (k <= 0) return ZKLAIM_ERROR;
    gcry_check_version(GCRYPT_VERSION);
    struct timespec t, t2;
    clock_t clock_begin, clock_end;
    size_t issuer_elapsed, prover_elapsed, verifier_elapsed;
    gcry_sexp_t priv, pub;
    zklaim_gen_pk(&priv);
    zklaim_get_pub(priv, &pub);
    unsigned char *pubbuf;
    size_t publen;
    zklaim_pub2buf(pub, &pubbuf, &publen);

    zklaim_ctx *ctx = zklaim_context_new();

    if (publen != 32) {
        printf("size mismatch!");
        return 1;
    }

    unsigned char trusted_issuer_key[32];
    memcpy(trusted_issuer_key, pubbuf, sizeof(trusted_issuer_key));
    free(pubbuf);

    /*
     * - 2 -
     * setup the first payload
     */
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
    for (int i=0; i<k; i++)
        zklaim_add_pl(ctx, pl);
    //zklaim_add_pl(ctx, pl2);
    //zklaim_add_pl(ctx, pl2);
    zklaim_hash_ctx(ctx);

    // Measures one setup per credential; issuers reuse it for every credential
    // with the same payload count.
    unsigned char *pk = NULL, *vk = NULL;
    size_t pk_size = 0, vk_size = 0;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t);
    zklaim_trusted_setup(ctx->num_of_payloads, &pk, &pk_size, &vk, &vk_size);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t2);

    issuer_elapsed = (t2.tv_sec-t.tv_sec)*1000 + (t2.tv_nsec-t.tv_nsec)/1000/1000;

    zklaim_ctx_sign(ctx, priv);

    // The verifier fixes the complete policy independently of the proof.
    // Only the first payload uses the requested age predicate; the remaining
    // payloads use the issuer's original predicates in this benchmark.
    zklaim_predicate *expected = calloc((size_t) k, sizeof(*expected));
    if (expected == NULL) {
        free(pk);
        free(vk);
        zklaim_ctx_free(ctx);
        gcry_sexp_release(priv);
        gcry_sexp_release(pub);
        return ZKLAIM_ERROR;
    }
    for (int i = 0; i < k; ++i) {
        memcpy(expected[i].data_ref, pl.data_ref, sizeof(pl.data_ref));
        memcpy(expected[i].data_op, pl.data_op, sizeof(pl.data_op));
    }
    expected[0].data_ref[0] = 20;
    for (size_t attr = 1; attr < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; ++attr) {
        expected[0].data_ref[attr] = 0;
        expected[0].data_op[attr] = zklaim_noop;
    }

    // The prover applies the verifier's request to the first payload.
    memcpy(ctx->pl_ctx_head->pl.data_ref, expected[0].data_ref, sizeof(expected[0].data_ref));
    memcpy(ctx->pl_ctx_head->pl.data_op, expected[0].data_op, sizeof(expected[0].data_op));

    unsigned char nonce[ZKLAIM_NONCE_SIZE];
    gcry_randomize(nonce, sizeof(nonce), GCRY_STRONG_RANDOM);

    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t);
    zklaim_proof_generate(ctx, pk, pk_size, nonce);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t2);

    prover_elapsed = (t2.tv_sec-t.tv_sec)*1000 + (t2.tv_nsec-t.tv_nsec)/1000/1000;

    zklaim_clear_pres(ctx);

    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t);
    const int verify_result = zklaim_ctx_verify(ctx, trusted_issuer_key, vk, vk_size,
                                                expected, (size_t) k, nonce);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t2);

    verifier_elapsed = (t2.tv_sec-t.tv_sec)*1000 + (t2.tv_nsec-t.tv_nsec)/1000/1000;

    printf("# of payloads: %zu\n", ctx->num_of_payloads);
    printf("issuer: %zums\n", issuer_elapsed);
    printf("prover: %zums\n", prover_elapsed);
    printf("verifier: %zums\n", verifier_elapsed);
    printf("proof: %zuB\n", ctx->proof_size);
    printf("vk: %zuB\n", vk_size);
    printf("pk: %zuB\n", pk_size);

    FILE *f;
    pthread_mutex_lock(&file_lock);
    char buf[32];
    snprintf(buf, sizeof(buf), "results-%i.csv", getpid());
    f = fopen(buf, "a");
    fprintf(f, "%lu,%zu,%zu,%zu,%zu,%zu,%zu,%zu\n", (unsigned long)time(NULL), ctx->num_of_payloads, issuer_elapsed, prover_elapsed, verifier_elapsed, pk_size, vk_size, ctx->proof_size);
    fclose(f);
    pthread_mutex_unlock(&file_lock);

    zklaim_ctx_free(ctx);
    free(expected);
    free(pk);
    free(vk);
    gcry_sexp_release(priv);
    gcry_sexp_release(pub);

    return verify_result;
}

void* thread_work(void* arg) {
#define RUNS 30
#define MAX_PL 20
    (void) arg;
    gcry_check_version(GCRYPT_VERSION);
    for (int i=1; i<=MAX_PL; i++) {
        for (int k=0; k<RUNS; k++) {
            worker(i);
        }
    }
    return NULL;
}

int main() {
#define THREADS 1
    gcry_check_version(GCRYPT_VERSION);
    pthread_t threads[THREADS];

    for (int i=0; i<THREADS; i++) {
        pthread_create(&threads[i], NULL, thread_work, NULL);
    }

    for (int i=0; i<THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
