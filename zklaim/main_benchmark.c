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
#include <semaphore.h>

static sem_t file_sem;

// to boost up valgrind
int worker(int k) {
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

    if (sizeof(ctx->pub_key) != publen) {
        printf("size mismatch!");
        return 1;
    }

    // TODO: there should be a zklaim method for this
    memcpy(ctx->pub_key, pubbuf, sizeof(ctx->pub_key));
    free(pubbuf);

    //print_sexp(pub);

    /*
     * - 2 -
     * setup the first payload
     */
    zklaim_payload pl, pl2;
    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data0_ref = 18;
    pl.data0_op = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data1_ref = 1;
    pl.data1_op = zklaim_eq;
    pl.data2_ref = 2;
    pl.data2_op = zklaim_eq;
    pl.data3_ref = 3;
    pl.data3_op = zklaim_eq;
    pl.data4_ref = 600;
    pl.data4_op = zklaim_less;
    pl.priv = 0;

    memset(&pl2, 0, sizeof(zklaim_payload));
    pl2.data0_ref = 0;
    pl2.data0_op = zklaim_noop;
    pl2.data1_ref = 0;
    pl2.data1_op = zklaim_noop;
    pl2.data2_ref = 0;
    pl2.data2_op = zklaim_noop;
    pl2.data3_ref = 0;
    pl2.data3_op = zklaim_noop;
    pl2.data4_ref = 9223372036854775807;
    pl2.data4_op = zklaim_less_or_eq;
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

    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t);
    zklaim_trusted_setup(ctx);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t2);

    issuer_elapsed = (t2.tv_sec-t.tv_sec)*1000 + (t2.tv_nsec-t.tv_nsec)/1000/1000;

    zklaim_ctx_sign(ctx, priv);

    // set custom prover reference values here:
    ctx->pl_ctx_head->pl.data0_ref = 20;
    //ctx_prover->pl_ctx_head->pl.data0_op = zklaim_less;
    ctx->pl_ctx_head->pl.data4_ref = 0;
    ctx->pl_ctx_head->pl.data4_op = zklaim_noop;

    ctx->pl_ctx_head->pl.data1_ref = 0;
    ctx->pl_ctx_head->pl.data1_op = zklaim_noop;

    ctx->pl_ctx_head->pl.data2_ref = 0;
    ctx->pl_ctx_head->pl.data2_op = zklaim_noop;

    ctx->pl_ctx_head->pl.data3_ref = 0;
    ctx->pl_ctx_head->pl.data3_op = zklaim_noop;

    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t);
    zklaim_proof_generate(ctx);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t2);

    prover_elapsed = (t2.tv_sec-t.tv_sec)*1000 + (t2.tv_nsec-t.tv_nsec)/1000/1000;

    zklaim_clear_pres(ctx);

    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t);
    zklaim_ctx_verify(ctx);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t2);

    verifier_elapsed = (t2.tv_sec-t.tv_sec)*1000 + (t2.tv_nsec-t.tv_nsec)/1000/1000;

    printf("# of payloads: %d\n", ctx->num_of_payloads);
    printf("issuer: %zums\n", issuer_elapsed);
    printf("prover: %zums\n", prover_elapsed);
    printf("verifier: %zums\n", verifier_elapsed);
    printf("proof: %zuB\n", ctx->proof_size);
    printf("vk: %zuB\n", ctx->vk_size);
    printf("pk: %zuB\n", ctx->pk_size);

    FILE *f;
    sem_wait(&file_sem);
    char buf[32];
    snprintf(buf, sizeof(buf), "results-%i.csv", getpid());
    f = fopen(buf, "a");
    fprintf(f, "%lu,%d,%zu,%zu,%zu,%zu,%zu,%zu\n", (unsigned long)time(NULL), ctx->num_of_payloads, issuer_elapsed, prover_elapsed, verifier_elapsed, ctx->pk_size, ctx->vk_size, ctx->proof_size);
    fclose(f);
    sem_post(&file_sem);

    zklaim_ctx_free(ctx);
    gcry_sexp_release(priv);
    gcry_sexp_release(pub);

    return ZKLAIM_OK;
}

void* thread_work() {
#define RUNS 30
#define MAX_PL 20
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
    sem_init(&file_sem, 0, 1);

    for (int i=0; i<THREADS; i++) {
        pthread_create(&threads[i], NULL, thread_work, NULL);
    }

    for (int i=0; i<THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
