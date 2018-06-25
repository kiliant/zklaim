#include <gtest/gtest.h>
extern "C" {
#include "zklaim.h"
}

TEST(zklaim, can_create_ctx) {
    zklaim_ctx *ctx = zklaim_context_new();
    ASSERT_TRUE(ctx);
}

TEST(zklaim, can_create_and_add_pl) {
    zklaim_payload pl;
    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data0_ref = 18;
    pl.data0_op = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data1_ref = 0;
    pl.data1_op = zklaim_eq;
    pl.data2_ref = 0;
    pl.data2_op = zklaim_eq;
    pl.data3_ref = 0;
    pl.data3_op = zklaim_eq;
    pl.data4_ref = 600;
    pl.data4_op = zklaim_less;
    pl.priv = 0;

    zklaim_ctx *ctx = zklaim_context_new();
    zklaim_add_pl(ctx, pl);

    ASSERT_FALSE(memcmp(&pl, &ctx->pl_ctx_head->pl, sizeof(zklaim_payload)));
}

TEST(zklaim, can_do_ts) {
    zklaim_payload pl;
    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data0_ref = 18;
    pl.data0_op = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data1_ref = 0;
    pl.data1_op = zklaim_eq;
    pl.data2_ref = 0;
    pl.data2_op = zklaim_eq;
    pl.data3_ref = 0;
    pl.data3_op = zklaim_eq;
    pl.data4_ref = 600;
    pl.data4_op = zklaim_less;
    pl.priv = 0;

    zklaim_ctx *ctx = zklaim_context_new();
    zklaim_add_pl(ctx, pl);

    ASSERT_FALSE(memcmp(&pl, &ctx->pl_ctx_head->pl, sizeof(zklaim_payload)));

    zklaim_hash_ctx(ctx);

    ASSERT_FALSE(zklaim_trusted_setup(ctx));
}

TEST(zklaim, can_sign) {
    zklaim_payload pl;
    gcry_sexp_t priv;

    zklaim_gen_pk(&priv);

    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data0_ref = 18;
    pl.data0_op = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data1_ref = 0;
    pl.data1_op = zklaim_eq;
    pl.data2_ref = 0;
    pl.data2_op = zklaim_eq;
    pl.data3_ref = 0;
    pl.data3_op = zklaim_eq;
    pl.data4_ref = 600;
    pl.data4_op = zklaim_less;
    pl.priv = 0;

    zklaim_ctx *ctx = zklaim_context_new();
    zklaim_add_pl(ctx, pl);

    ASSERT_FALSE(memcmp(&pl, &ctx->pl_ctx_head->pl, sizeof(zklaim_payload)));

    zklaim_hash_ctx(ctx);

    ASSERT_FALSE(zklaim_trusted_setup(ctx));
    ASSERT_FALSE(zklaim_ctx_sign(ctx, priv));
}

TEST(zklaim, can_detect_invalid_signature) {
    gcry_sexp_t priv, pub;
    zklaim_gen_pk(&priv);
    zklaim_get_pub(priv, &pub);
    unsigned char *pubbuf;
    size_t publen;
    zklaim_pub2buf(pub, &pubbuf, &publen);

    zklaim_ctx *ctx = zklaim_context_new();

    if (sizeof(ctx->pub_key) != publen) {
        ASSERT_FALSE(1);
    }

    memcpy(ctx->pub_key, pubbuf, sizeof(ctx->pub_key));

    zklaim_payload pl, pl2;
    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data0_ref = 18;
    pl.data0_op = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data1_ref = 0;
    pl.data1_op = zklaim_eq;
    pl.data2_ref = 0;
    pl.data2_op = zklaim_eq;
    pl.data3_ref = 0;
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

    zklaim_set_attr(&pl, 18, 0);
    zklaim_set_attr(&pl, 0, 1);
    zklaim_set_attr(&pl, 0, 2);
    zklaim_set_attr(&pl, 0, 3);
    zklaim_set_attr(&pl, 599, 4);

    zklaim_set_attr(&pl2, 0, 0);
    zklaim_set_attr(&pl2, 0, 1);
    zklaim_set_attr(&pl2, 0, 2);
    zklaim_set_attr(&pl2, 0, 3);
    zklaim_set_attr(&pl2, 9223372036854775807, 4);

    zklaim_add_pl(ctx, pl);
    zklaim_add_pl(ctx, pl2);

    zklaim_hash_ctx(ctx);

    ASSERT_FALSE(zklaim_ctx_sign(ctx, priv));

    unsigned char* ctx_issuer;

    size_t len = zklaim_ctx_serialize(ctx, &ctx_issuer);

    zklaim_ctx* ctx_prover = zklaim_context_new();
    ASSERT_FALSE(zklaim_ctx_deserialize(ctx_prover, ctx_issuer, len));

    //ctx_prover->pk = ctx->pk;

    ctx_prover->pk = (unsigned char*) calloc(1, ctx->pk_size);
    ctx_prover->pk_size = ctx->pk_size;
    memcpy(ctx_prover->pk, ctx->pk, ctx_prover->pk_size);

    ctx_prover->pl_ctx_head->pl.data0_ref = 19;
    zklaim_hash_ctx(ctx_prover);

    zklaim_clear_pres(ctx_prover);

    unsigned char *ctx_prover_buf;
    len = zklaim_ctx_serialize(ctx_prover, &ctx_prover_buf);

    zklaim_ctx* ctx_verifier = zklaim_context_new();

    ASSERT_FALSE(zklaim_ctx_deserialize(ctx_verifier, ctx_prover_buf, len));

    ASSERT_TRUE(zklaim_ctx_verify(ctx_verifier));
}

TEST(DISABLED_zklaim, can_serialize) {
}

TEST(DISABLED_zklaim, can_deserialize) {
}

TEST(zklaim, can_verify) {
    zklaim_payload pl;
    gcry_sexp_t priv, pub;

    zklaim_gen_pk(&priv);
    zklaim_get_pub(priv, &pub);
    unsigned char *pubbuf;
    size_t publen;
    zklaim_pub2buf(pub, &pubbuf, &publen);

    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data0_ref = 18;
    pl.data0_op = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data1_ref = 0;
    pl.data1_op = zklaim_eq;
    pl.data2_ref = 0;
    pl.data2_op = zklaim_eq;
    pl.data3_ref = 0;
    pl.data3_op = zklaim_eq;
    pl.data4_ref = 600;
    pl.data4_op = zklaim_less;
    pl.priv = 0;


    zklaim_ctx *ctx = zklaim_context_new();
    zklaim_add_pl(ctx, pl);

    ASSERT_FALSE(memcmp(&pl, &ctx->pl_ctx_head->pl, sizeof(zklaim_payload)));

    zklaim_hash_ctx(ctx);

    memcpy(ctx->pub_key, pubbuf, sizeof(ctx->pub_key));

    ASSERT_FALSE(zklaim_trusted_setup(ctx));
    ASSERT_FALSE(zklaim_ctx_sign(ctx, priv));
    ASSERT_TRUE(zklaim_ctx_verify(ctx) == ZKLAIM_INVALID_PROOF);
    free(pubbuf);
}

TEST(zklaim, can_proof) {
    zklaim_payload pl;
    gcry_sexp_t priv;

    zklaim_gen_pk(&priv);

    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data0_ref = 18;
    pl.data0_op = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data1_ref = 0;
    pl.data1_op = zklaim_eq;
    pl.data2_ref = 0;
    pl.data2_op = zklaim_eq;
    pl.data3_ref = 0;
    pl.data3_op = zklaim_eq;
    pl.data4_ref = 600;
    pl.data4_op = zklaim_less;
    pl.priv = 0;

    zklaim_set_attr(&pl, 18, 0);
    zklaim_set_attr(&pl, 0, 1);
    zklaim_set_attr(&pl, 0, 2);
    zklaim_set_attr(&pl, 0, 3);
    zklaim_set_attr(&pl, 599, 4);


    zklaim_ctx *ctx = zklaim_context_new();
    zklaim_add_pl(ctx, pl);

    ASSERT_FALSE(memcmp(&pl, &ctx->pl_ctx_head->pl, sizeof(zklaim_payload)));

    zklaim_hash_ctx(ctx);

    ASSERT_FALSE(zklaim_trusted_setup(ctx));
    ASSERT_FALSE(zklaim_ctx_sign(ctx, priv));
    ASSERT_FALSE(zklaim_proof_generate(ctx));
}

TEST(zklaim, can_handle_two_payloads) {
    zklaim_payload pl;
    gcry_sexp_t priv;

    zklaim_gen_pk(&priv);

    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data0_ref = 18;
    pl.data0_op = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data1_ref = 0;
    pl.data1_op = zklaim_eq;
    pl.data2_ref = 0;
    pl.data2_op = zklaim_eq;
    pl.data3_ref = 0;
    pl.data3_op = zklaim_eq;
    pl.data4_ref = 600;
    pl.data4_op = zklaim_less;
    pl.priv = 0;

    zklaim_set_attr(&pl, 18, 0);
    zklaim_set_attr(&pl, 0, 1);
    zklaim_set_attr(&pl, 0, 2);
    zklaim_set_attr(&pl, 0, 3);
    zklaim_set_attr(&pl, 599, 4);


    zklaim_ctx *ctx = zklaim_context_new();
    zklaim_add_pl(ctx, pl);
    zklaim_add_pl(ctx, pl);

    ASSERT_FALSE(memcmp(&pl, &ctx->pl_ctx_head->pl, sizeof(zklaim_payload)));

    zklaim_hash_ctx(ctx);

    ASSERT_FALSE(zklaim_trusted_setup(ctx));
    ASSERT_FALSE(zklaim_ctx_sign(ctx, priv));
    ASSERT_FALSE(zklaim_proof_generate(ctx));

}

TEST(zklaim, can_handle_three_payloads) {
    zklaim_payload pl;
    gcry_sexp_t priv;

    zklaim_gen_pk(&priv);

    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data0_ref = 18;
    pl.data0_op = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data1_ref = 0;
    pl.data1_op = zklaim_eq;
    pl.data2_ref = 0;
    pl.data2_op = zklaim_eq;
    pl.data3_ref = 0;
    pl.data3_op = zklaim_eq;
    pl.data4_ref = 600;
    pl.data4_op = zklaim_less;
    pl.priv = 0;

    zklaim_set_attr(&pl, 18, 0);
    zklaim_set_attr(&pl, 0, 1);
    zklaim_set_attr(&pl, 0, 2);
    zklaim_set_attr(&pl, 0, 3);
    zklaim_set_attr(&pl, 599, 4);


    zklaim_ctx *ctx = zklaim_context_new();
    zklaim_add_pl(ctx, pl);
    zklaim_add_pl(ctx, pl);
    zklaim_add_pl(ctx, pl);

    ASSERT_FALSE(memcmp(&pl, &ctx->pl_ctx_head->pl, sizeof(zklaim_payload)));

    zklaim_hash_ctx(ctx);

    ASSERT_FALSE(zklaim_trusted_setup(ctx));
    ASSERT_FALSE(zklaim_ctx_sign(ctx, priv));
    ASSERT_FALSE(zklaim_proof_generate(ctx));

}

TEST(zklaim, can_handle_no_payload) {
    gcry_sexp_t priv;

    zklaim_gen_pk(&priv);

    zklaim_ctx *ctx = zklaim_context_new();

    zklaim_hash_ctx(ctx);

    ASSERT_FALSE(zklaim_trusted_setup(ctx));
    ASSERT_FALSE(zklaim_ctx_sign(ctx, priv));
    ASSERT_FALSE(zklaim_proof_generate(ctx));
}

TEST(DISABLED_zklaim, can_handle_mismatching_payloads) {
    // TODO
}

TEST(DISABLED_zklaim, detect_forged_signature) {
    // TODO
}

TEST(DISABLED_zklaim, detect_forged_values_in_circuit) {
    // TODO
}

TEST(DISABLED_zklaim, rejects_invalid_proof) {
    // TODO
}


TEST(zklaim, preimage_and_salt_get_cleared) {
    zklaim_payload pl;
    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data0_ref = 18;
    pl.data0_op = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data1_ref = 0;
    pl.data1_op = zklaim_eq;
    pl.data2_ref = 0;
    pl.data2_op = zklaim_eq;
    pl.data3_ref = 0;
    pl.data3_op = zklaim_eq;
    pl.data4_ref = 600;
    pl.data4_op = zklaim_less;
    pl.priv = 0;

    zklaim_set_attr(&pl, 18, 0);
    zklaim_set_attr(&pl, 0, 1);
    zklaim_set_attr(&pl, 0, 2);
    zklaim_set_attr(&pl, 0, 3);
    zklaim_set_attr(&pl, 599, 4);

    zklaim_ctx *ctx = zklaim_context_new();
    zklaim_add_pl(ctx, pl);

    ASSERT_FALSE(memcmp(&pl, &ctx->pl_ctx_head->pl, sizeof(zklaim_payload)));

    zklaim_hash_ctx(ctx);

    zklaim_clear_pres(ctx);

    ASSERT_FALSE(ctx->pl_ctx_head->pl.salt);

    unsigned char *p = ctx->pl_ctx_head->pl.pre;

    for(size_t i=0; i<sizeof(ctx->pl_ctx_head->pl.pre); i++) {
        if (0 != (unsigned char) *p) {
            ASSERT_FALSE(1);
        }
    }
}

TEST(zklaim, three_party_run) {
    gcry_sexp_t priv, pub;
    zklaim_gen_pk(&priv);
    zklaim_get_pub(priv, &pub);
    unsigned char *pubbuf;
    size_t publen;
    zklaim_pub2buf(pub, &pubbuf, &publen);

    zklaim_ctx *ctx = zklaim_context_new();

    if (sizeof(ctx->pub_key) != publen) {
        ASSERT_FALSE(1);
    }

    memcpy(ctx->pub_key, pubbuf, sizeof(ctx->pub_key));

    zklaim_payload pl, pl2;
    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data0_ref = 18;
    pl.data0_op = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data1_ref = 0;
    pl.data1_op = zklaim_eq;
    pl.data2_ref = 0;
    pl.data2_op = zklaim_eq;
    pl.data3_ref = 0;
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

    zklaim_set_attr(&pl, 18, 0);
    zklaim_set_attr(&pl, 0, 1);
    zklaim_set_attr(&pl, 0, 2);
    zklaim_set_attr(&pl, 0, 3);
    zklaim_set_attr(&pl, 599, 4);

    zklaim_set_attr(&pl2, 0, 0);
    zklaim_set_attr(&pl2, 0, 1);
    zklaim_set_attr(&pl2, 0, 2);
    zklaim_set_attr(&pl2, 0, 3);
    zklaim_set_attr(&pl2, 9223372036854775807, 4);

    zklaim_add_pl(ctx, pl);
    zklaim_add_pl(ctx, pl2);

    zklaim_hash_ctx(ctx);

    ASSERT_FALSE(zklaim_trusted_setup(ctx));

    ASSERT_FALSE(zklaim_ctx_sign(ctx, priv));

    unsigned char* ctx_issuer;

    size_t len = zklaim_ctx_serialize(ctx, &ctx_issuer);

    zklaim_ctx* ctx_prover = zklaim_context_new();
    ASSERT_FALSE(zklaim_ctx_deserialize(ctx_prover, ctx_issuer, len));

    //ctx_prover->pk = ctx->pk;

    ctx_prover->pk = (unsigned char*) calloc(1, ctx->pk_size);
    ctx_prover->pk_size = ctx->pk_size;
    memcpy(ctx_prover->pk, ctx->pk, ctx_prover->pk_size);

    int res = zklaim_ctx_verify(ctx_prover);

    ASSERT_FALSE(zklaim_proof_generate(ctx_prover));

    zklaim_clear_pres(ctx_prover);

    unsigned char *ctx_prover_buf;
    len = zklaim_ctx_serialize(ctx_prover, &ctx_prover_buf);

    zklaim_ctx* ctx_verifier = zklaim_context_new();

    ASSERT_FALSE(zklaim_ctx_deserialize(ctx_verifier, ctx_prover_buf, len));
    res = zklaim_ctx_verify(ctx_verifier);
    ASSERT_FALSE(res);
}

