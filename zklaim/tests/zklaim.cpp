#include <gtest/gtest.h>
#include <sstream>
#include <cerrno>
#include <map>
#include <memory>
#include <fcntl.h>
#include <openssl/sha.h>
#include <sys/resource.h>
#include "../snark.hpp"
extern "C" {
#include <zklaim/zklaim.h>
}

struct zklaim_test_keys {
    unsigned char *pk = nullptr;
    unsigned char *vk = nullptr;
    size_t pk_size = 0;
    size_t vk_size = 0;
    ~zklaim_test_keys() { free(pk); free(vk); }
};

// One trusted setup per payload count serves every credential with that count.
static const zklaim_test_keys &zklaim_keys_for(size_t payloads) {
    static std::map<size_t, std::unique_ptr<zklaim_test_keys> > cache;
    auto &keys = cache[payloads];
    if (!keys) {
        keys.reset(new zklaim_test_keys);
        if (zklaim_trusted_setup(payloads, &keys->pk, &keys->pk_size,
                                 &keys->vk, &keys->vk_size) != ZKLAIM_OK) {
            ADD_FAILURE() << "trusted setup failed for " << payloads << " payloads";
        }
    }
    return *keys;
}

static const unsigned char zklaim_test_nonce[ZKLAIM_NONCE_SIZE] = {
    0x6e, 0x6f, 0x6e, 0x63, 0x65, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 0xff
};

TEST(zklaim, can_create_ctx) {
    zklaim_ctx *ctx = zklaim_context_new();
    ASSERT_TRUE(ctx);
}

TEST(zklaim, snark_calls_preserve_stdout_and_file_descriptors) {
    std::unique_ptr<zklaim_ctx, decltype(&zklaim_ctx_free)> ctx(
        zklaim_context_new(), zklaim_ctx_free);
    ASSERT_NE(nullptr, ctx);
    zklaim_payload pl = {};
    for (auto &op : pl.data_op) op = zklaim_noop;
    pl.data_op[0] = zklaim_eq;
    pl.data_ref[0] = 42;
    ASSERT_EQ(ZKLAIM_OK, zklaim_set_attr(&pl, 42, 0));
    zklaim_add_pl(ctx.get(), pl);
    zklaim_hash_ctx(ctx.get());

    // dup returns the lowest free descriptor, so a leaked descriptor changes it.
    const int next_fd = dup(STDOUT_FILENO);
    ASSERT_GE(next_fd, 0);
    close(next_fd);
    clearerr(stdout);
    auto expect_stdout_intact = [&]() {
        EXPECT_EQ(0, ferror(stdout));
        const int fd = dup(STDOUT_FILENO);
        EXPECT_EQ(next_fd, fd);
        if (fd >= 0) close(fd);
    };

    zklaim_test_keys keys;
    EXPECT_EQ(ZKLAIM_OK, zklaim_trusted_setup(1, &keys.pk, &keys.pk_size, &keys.vk, &keys.vk_size));
    expect_stdout_intact();
    EXPECT_EQ(ZKLAIM_OK, zklaim_proof_generate(ctx.get(), keys.pk, keys.pk_size, zklaim_test_nonce));
    expect_stdout_intact();
    for (int i = 0; i < 5; ++i) {
        EXPECT_EQ(ZKLAIM_OK, zklaim_proof_verify(ctx.get(), keys.vk, keys.vk_size, zklaim_test_nonce));
        expect_stdout_intact();
    }
    // libsnark prints a warning for a verification key of another payload count.
    const auto &two = zklaim_keys_for(2);
    ::testing::internal::CaptureStdout();
    EXPECT_NE(ZKLAIM_OK, zklaim_proof_verify(ctx.get(), two.vk, two.vk_size, zklaim_test_nonce));
    EXPECT_EQ("", ::testing::internal::GetCapturedStdout());
    expect_stdout_intact();
    ctx->pl_ctx_head->pl.data_ref[0] = 43;
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_proof_generate(ctx.get(), keys.pk, keys.pk_size, zklaim_test_nonce));
    expect_stdout_intact();

    ::testing::internal::CaptureStdout();
    EXPECT_GT(printf("caller stdout still works\n"), 0);
    EXPECT_EQ(0, fflush(stdout));
    const std::string output = ::testing::internal::GetCapturedStdout();
    EXPECT_NE(std::string::npos, output.find("caller stdout still works"));
}

TEST(zklaimDeathTest, can_free_null_context) {
    ASSERT_EXIT({
        zklaim_ctx_free(NULL);
        _exit(0);
    }, ::testing::ExitedWithCode(0), "");
}

TEST(zklaimDeathTest, frees_context_with_untrusted_payload_count) {
    ASSERT_EXIT({
        zklaim_ctx *ctx = zklaim_context_new();
        if (ctx == NULL) _exit(1);
        zklaim_payload pl = {};
        zklaim_add_pl(ctx, pl);
        zklaim_add_pl(ctx, pl);
        ctx->num_of_payloads = SIZE_MAX;
        zklaim_ctx_free(ctx);
        _exit(0);
    }, ::testing::ExitedWithCode(0), "");
}

TEST(zklaim, frees_context_storage_with_zero_metadata) {
    // Also run under a leak detector to check that every allocation is released.
    zklaim_ctx *ctx = zklaim_context_new();
    ASSERT_NE(nullptr, ctx);
    zklaim_payload pl = {};
    zklaim_add_pl(ctx, pl);
    zklaim_add_pl(ctx, pl);
    ctx->num_of_payloads = 0;
    // Allocations can be non-null even when their serialized size is zero.
    ctx->proof = static_cast<unsigned char *>(malloc(1));
    ASSERT_NE(nullptr, ctx->proof);
    zklaim_ctx_free(ctx);
}

TEST(zklaim, rejects_invalid_attribute_positions) {
    zklaim_payload pl;
    memset(&pl, 0xa5, sizeof(pl));
    unsigned char original[sizeof(pl)];
    memcpy(original, &pl, sizeof(pl));

    // Position 5 is the salt slot; larger positions must also be rejected.
    for (uint8_t pos : {ZKLAIM_MAX_PAYLOAD_ATTRIBUTES, 6, 255}) {
        SCOPED_TRACE(static_cast<unsigned int>(pos));
        memcpy(&pl, original, sizeof(pl));
        EXPECT_EQ(ZKLAIM_ERROR,
                  zklaim_set_attr(&pl, UINT64_C(0x4141414141414141), pos));
        EXPECT_EQ(0, memcmp(original, &pl, sizeof(pl)));
    }
}

TEST(zklaim, can_set_all_attribute_slots) {
    zklaim_payload pl = {};
    memset(pl.pre, 0xa5, sizeof(pl.pre));
    memset(pl.salt, 0x5a, sizeof(pl.salt));
    const uint64_t values[ZKLAIM_MAX_PAYLOAD_ATTRIBUTES] = {
        0, 1, UINT64_C(0x0123456789abcdef),
        UINT64_C(0x8000000000000000), UINT64_MAX
    };

    for (uint8_t pos = 0; pos < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; ++pos) {
        SCOPED_TRACE(static_cast<unsigned int>(pos));
        ASSERT_EQ(ZKLAIM_OK, zklaim_set_attr(&pl, values[pos], pos));
    }

    uint64_t actual[ZKLAIM_MAX_PAYLOAD_ATTRIBUTES];
    for (uint8_t pos = 0; pos < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; ++pos) {
        ASSERT_EQ(ZKLAIM_OK, zklaim_get_attr(&pl, pos, &actual[pos]));
    }
    for (size_t pos = 0; pos < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; ++pos) {
        SCOPED_TRACE(pos);
        EXPECT_EQ(values[pos], actual[pos]);
    }
    static_assert(sizeof(actual) + ZKLAIM_SALT_SIZE == sizeof(pl.pre), "salt follows the attributes");
    for (size_t i = sizeof(actual); i < sizeof(pl.pre); ++i) EXPECT_EQ(0xa5, pl.pre[i]);
    for (unsigned char byte : pl.salt) EXPECT_EQ(0x5a, byte);
}

TEST(zklaimDeathTest, hashes_payload_when_file_descriptors_are_exhausted) {
    ASSERT_EXIT({
        // Initialize libgcrypt's entropy source before exhausting descriptors.
        unsigned char seed[8];
        gcry_randomize(seed, sizeof(seed), GCRY_STRONG_RANDOM);
        struct rlimit limit;
        if (getrlimit(RLIMIT_NOFILE, &limit) != 0) _exit(1);
        limit.rlim_cur = 0;
        if (setrlimit(RLIMIT_NOFILE, &limit) != 0) _exit(2);
        if (open("/dev/urandom", O_RDONLY) != -1 || errno != EMFILE) _exit(3);

        zklaim_payload pl = {};
        unsigned char previous[ZKLAIM_SALT_SIZE];
        memset(previous, 0x5a, sizeof(previous));
        memcpy(pl.salt, previous, sizeof(pl.salt));
        zklaim_hash_pl(&pl);
        if (memcmp(pl.salt, previous, sizeof(previous)) == 0) _exit(4);
        if (memcmp(pl.pre + ZKLAIM_MAX_PAYLOAD_ATTRIBUTES * sizeof(uint64_t), pl.salt, sizeof(pl.salt)) != 0) _exit(5);
        _exit(0);
    }, ::testing::ExitedWithCode(0), "");
}

TEST(zklaim, payload_hash_includes_fresh_salt) {
    zklaim_payload pl = {};
    memset(pl.pre, 0xa5, sizeof(pl.pre));
    zklaim_hash_pl(&pl);

    // 40 attribute bytes and a 15-byte salt: the largest message SHA-256 pads into one block.
    ASSERT_EQ(55u, sizeof(pl.pre));
    EXPECT_EQ(0, memcmp(pl.salt, pl.pre + ZKLAIM_MAX_PAYLOAD_ATTRIBUTES * sizeof(uint64_t), sizeof(pl.salt)));
    unsigned char expected[32];
    SHA256(pl.pre, sizeof(pl.pre), expected);
    EXPECT_EQ(0, memcmp(expected, pl.hash, sizeof(expected)));
    for (size_t i = 0; i < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES * sizeof(uint64_t); ++i) {
        EXPECT_EQ(0xa5, pl.pre[i]);
    }
    zklaim_payload again = pl;
    zklaim_hash_pl(&again);
    EXPECT_NE(0, memcmp(pl.salt, again.salt, sizeof(pl.salt)));
    EXPECT_NE(0, memcmp(pl.hash, again.hash, sizeof(pl.hash)));
}

TEST(zklaim, can_create_and_add_pl) {
    zklaim_payload pl;
    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data_ref[0] = 18;
    pl.data_op[0] = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data_ref[1] = 0;
    pl.data_op[1] = zklaim_eq;
    pl.data_ref[2] = 0;
    pl.data_op[2] = zklaim_eq;
    pl.data_ref[3] = 0;
    pl.data_op[3] = zklaim_eq;
    pl.data_ref[4] = 600;
    pl.data_op[4] = zklaim_less;
    pl.priv = 0;

    zklaim_ctx *ctx = zklaim_context_new();
    ASSERT_EQ(ZKLAIM_OK, zklaim_add_pl(ctx, pl));

    ASSERT_FALSE(memcmp(&pl, &ctx->pl_ctx_head->pl, sizeof(zklaim_payload)));
}

TEST(zklaim, payload_insertion_rejects_invalid_context_without_mutation) {
    zklaim_payload pl = {};
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_add_pl(nullptr, pl));
    std::unique_ptr<zklaim_ctx, decltype(&zklaim_ctx_free)> ctx(
        zklaim_context_new(), zklaim_ctx_free);
    ASSERT_NE(nullptr, ctx);
    ctx->num_of_payloads = UINT32_MAX;
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_add_pl(ctx.get(), pl));
    EXPECT_EQ(nullptr, ctx->pl_ctx_head);
    EXPECT_EQ(static_cast<size_t>(UINT32_MAX), ctx->num_of_payloads);
}

TEST(zklaim, can_do_ts) {
    zklaim_payload pl;
    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data_ref[0] = 18;
    pl.data_op[0] = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data_ref[1] = 0;
    pl.data_op[1] = zklaim_eq;
    pl.data_ref[2] = 0;
    pl.data_op[2] = zklaim_eq;
    pl.data_ref[3] = 0;
    pl.data_op[3] = zklaim_eq;
    pl.data_ref[4] = 600;
    pl.data_op[4] = zklaim_less;
    pl.priv = 0;

    zklaim_ctx *ctx = zklaim_context_new();
    zklaim_add_pl(ctx, pl);

    ASSERT_FALSE(memcmp(&pl, &ctx->pl_ctx_head->pl, sizeof(zklaim_payload)));

    zklaim_hash_ctx(ctx);

    const auto &keys = zklaim_keys_for(ctx->num_of_payloads);
    ASSERT_NE(nullptr, keys.pk);
    ASSERT_NE(nullptr, keys.vk);
    EXPECT_GT(keys.pk_size, 0u);
    EXPECT_GT(keys.vk_size, 0u);
    zklaim_ctx_free(ctx);
}

TEST(zklaim, trusted_setup_rejects_invalid_arguments_without_output) {
    unsigned char marker = 0;
    unsigned char *pk = &marker, *vk = &marker;
    size_t pk_size = 1, vk_size = 1;
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_trusted_setup(0, &pk, &pk_size, &vk, &vk_size));
    EXPECT_EQ(nullptr, pk);
    EXPECT_EQ(nullptr, vk);
    EXPECT_EQ(0u, pk_size);
    EXPECT_EQ(0u, vk_size);
#if SIZE_MAX > UINT32_MAX
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_trusted_setup(static_cast<size_t>(UINT32_MAX) + 1,
                                                 &pk, &pk_size, &vk, &vk_size));
#endif
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_trusted_setup(1, nullptr, &pk_size, &vk, &vk_size));
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_trusted_setup(1, &pk, nullptr, &vk, &vk_size));
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_trusted_setup(1, &pk, &pk_size, nullptr, &vk_size));
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_trusted_setup(1, &pk, &pk_size, &vk, nullptr));
}

static int context_sign_failure_result(gcry_sexp_t key) {
    zklaim_ctx ctx = {};
    memset(ctx.signature, 0xa5, sizeof(ctx.signature));
    memset(ctx.pub_key, 0x5a, sizeof(ctx.pub_key));
    zklaim_ctx original = ctx;
    if (zklaim_ctx_sign(&ctx, key) != ZKLAIM_ERROR) return 1;
    if (memcmp(original.signature, ctx.signature, sizeof(ctx.signature)) != 0) return 2;
    if (memcmp(original.pub_key, ctx.pub_key, sizeof(ctx.pub_key)) != 0) return 3;
    return 0;
}

TEST(zklaimDeathTest, signing_rejects_public_only_key) {
    ASSERT_EXIT({
        gcry_sexp_t priv;
        gcry_sexp_t pub;
        if (zklaim_gen_pk(&priv) || zklaim_get_pub(priv, &pub)) _exit(3);
        int result = context_sign_failure_result(pub);
        gcry_sexp_release(pub);
        gcry_sexp_release(priv);
        _exit(result);
    }, ::testing::ExitedWithCode(0), "");
}

TEST(zklaimDeathTest, signing_rejects_non_ecdsa_signature) {
    ASSERT_EXIT({
        gcry_sexp_t params;
        gcry_sexp_t priv;
        if (gcry_sexp_build(&params, NULL, "(genkey(rsa(nbits 4:2048)))")) _exit(3);
        if (gcry_pk_genkey(&priv, params)) _exit(4);
        int result = context_sign_failure_result(priv);
        gcry_sexp_release(priv);
        gcry_sexp_release(params);
        _exit(result);
    }, ::testing::ExitedWithCode(0), "");
}

TEST(zklaim, can_sign) {
    zklaim_payload pl;
    gcry_sexp_t priv;

    zklaim_gen_pk(&priv);

    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data_ref[0] = 18;
    pl.data_op[0] = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data_ref[1] = 0;
    pl.data_op[1] = zklaim_eq;
    pl.data_ref[2] = 0;
    pl.data_op[2] = zklaim_eq;
    pl.data_ref[3] = 0;
    pl.data_op[3] = zklaim_eq;
    pl.data_ref[4] = 600;
    pl.data_op[4] = zklaim_less;
    pl.priv = 0;

    zklaim_ctx *ctx = zklaim_context_new();
    zklaim_add_pl(ctx, pl);

    ASSERT_FALSE(memcmp(&pl, &ctx->pl_ctx_head->pl, sizeof(zklaim_payload)));

    zklaim_hash_ctx(ctx);

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
    pl.data_ref[0] = 18;
    pl.data_op[0] = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data_ref[1] = 0;
    pl.data_op[1] = zklaim_eq;
    pl.data_ref[2] = 0;
    pl.data_op[2] = zklaim_eq;
    pl.data_ref[3] = 0;
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

    zklaim_predicate expected[2] = {};
    memcpy(expected[0].data_ref, pl.data_ref, sizeof(pl.data_ref));
    memcpy(expected[0].data_op, pl.data_op, sizeof(pl.data_op));
    memcpy(expected[1].data_ref, pl2.data_ref, sizeof(pl2.data_ref));
    memcpy(expected[1].data_op, pl2.data_op, sizeof(pl2.data_op));

    zklaim_hash_ctx(ctx);

    ASSERT_FALSE(zklaim_ctx_sign(ctx, priv));

    unsigned char* ctx_issuer;

    size_t len = zklaim_ctx_serialize_credential(ctx, &ctx_issuer);

    zklaim_ctx* ctx_prover = zklaim_context_new();
    ASSERT_FALSE(zklaim_ctx_deserialize(ctx_prover, ctx_issuer, len));

    zklaim_set_attr(&ctx_prover->pl_ctx_head->pl, 19, 0);
    zklaim_hash_ctx(ctx_prover);

    zklaim_clear_pres(ctx_prover);

    unsigned char *ctx_prover_buf;
    len = zklaim_ctx_serialize(ctx_prover, &ctx_prover_buf);

    zklaim_ctx* ctx_verifier = zklaim_context_new();

    ASSERT_FALSE(zklaim_ctx_deserialize(ctx_verifier, ctx_prover_buf, len));

    const auto &keys = zklaim_keys_for(2);
    ASSERT_EQ(ZKLAIM_INVALID_SIGNATURE,
              zklaim_ctx_verify(ctx_verifier, pubbuf, keys.vk, keys.vk_size, expected, 2,
                                zklaim_test_nonce));
    free(pubbuf);
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
    pl.data_ref[0] = 18;
    pl.data_op[0] = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data_ref[1] = 0;
    pl.data_op[1] = zklaim_eq;
    pl.data_ref[2] = 0;
    pl.data_op[2] = zklaim_eq;
    pl.data_ref[3] = 0;
    pl.data_op[3] = zklaim_eq;
    pl.data_ref[4] = 600;
    pl.data_op[4] = zklaim_less;
    pl.priv = 0;


    zklaim_ctx *ctx = zklaim_context_new();
    zklaim_add_pl(ctx, pl);

    zklaim_predicate expected = {};
    memcpy(expected.data_ref, pl.data_ref, sizeof(pl.data_ref));
    memcpy(expected.data_op, pl.data_op, sizeof(pl.data_op));

    ASSERT_FALSE(memcmp(&pl, &ctx->pl_ctx_head->pl, sizeof(zklaim_payload)));

    zklaim_hash_ctx(ctx);

    memcpy(ctx->pub_key, pubbuf, sizeof(ctx->pub_key));

    const auto &keys = zklaim_keys_for(1);
    ASSERT_FALSE(zklaim_ctx_sign(ctx, priv));
    ASSERT_EQ(ZKLAIM_INVALID_PROOF, zklaim_ctx_verify(ctx, pubbuf, keys.vk, keys.vk_size,
                                                      &expected, 1, zklaim_test_nonce));
    free(pubbuf);
}

TEST(zklaim, can_proof) {
    zklaim_payload pl;
    gcry_sexp_t priv;

    zklaim_gen_pk(&priv);

    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data_ref[0] = 18;
    pl.data_op[0] = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data_ref[1] = 0;
    pl.data_op[1] = zklaim_eq;
    pl.data_ref[2] = 0;
    pl.data_op[2] = zklaim_eq;
    pl.data_ref[3] = 0;
    pl.data_op[3] = zklaim_eq;
    pl.data_ref[4] = 600;
    pl.data_op[4] = zklaim_less;
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

    const auto &keys = zklaim_keys_for(ctx->num_of_payloads);
    ASSERT_FALSE(zklaim_ctx_sign(ctx, priv));
    ASSERT_FALSE(zklaim_proof_generate(ctx, keys.pk, keys.pk_size, zklaim_test_nonce));
    ASSERT_FALSE(zklaim_proof_verify(ctx, keys.vk, keys.vk_size, zklaim_test_nonce));
}

TEST(zklaim, can_handle_two_payloads) {
    zklaim_payload pl;
    gcry_sexp_t priv;

    zklaim_gen_pk(&priv);

    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data_ref[0] = 18;
    pl.data_op[0] = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data_ref[1] = 0;
    pl.data_op[1] = zklaim_eq;
    pl.data_ref[2] = 0;
    pl.data_op[2] = zklaim_eq;
    pl.data_ref[3] = 0;
    pl.data_op[3] = zklaim_eq;
    pl.data_ref[4] = 600;
    pl.data_op[4] = zklaim_less;
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

    const auto &keys = zklaim_keys_for(ctx->num_of_payloads);
    ASSERT_FALSE(zklaim_ctx_sign(ctx, priv));
    ASSERT_FALSE(zklaim_proof_generate(ctx, keys.pk, keys.pk_size, zklaim_test_nonce));
    ASSERT_FALSE(zklaim_proof_verify(ctx, keys.vk, keys.vk_size, zklaim_test_nonce));

}

TEST(zklaim, can_handle_three_payloads) {
    zklaim_payload pl;
    gcry_sexp_t priv;

    zklaim_gen_pk(&priv);

    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data_ref[0] = 18;
    pl.data_op[0] = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data_ref[1] = 0;
    pl.data_op[1] = zklaim_eq;
    pl.data_ref[2] = 0;
    pl.data_op[2] = zklaim_eq;
    pl.data_ref[3] = 0;
    pl.data_op[3] = zklaim_eq;
    pl.data_ref[4] = 600;
    pl.data_op[4] = zklaim_less;
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

    const auto &keys = zklaim_keys_for(ctx->num_of_payloads);
    ASSERT_FALSE(zklaim_ctx_sign(ctx, priv));
    ASSERT_FALSE(zklaim_proof_generate(ctx, keys.pk, keys.pk_size, zklaim_test_nonce));
    ASSERT_FALSE(zklaim_proof_verify(ctx, keys.vk, keys.vk_size, zklaim_test_nonce));

}

TEST(zklaim, rejects_contexts_without_payloads) {
    int (*operations[])(zklaim_ctx *, const unsigned char *, size_t, const unsigned char *) = {
        zklaim_proof_generate, zklaim_proof_verify
    };
    const auto &keys = zklaim_keys_for(1);
    zklaim_wrap_payload_ctx payload = {};
    unsigned char existing[] = {1, 2, 3};
    zklaim_ctx ctx = {};
    ctx.proof = existing;
    ctx.proof_size = sizeof(existing);

    // Neither a count without a list nor a list without a count is provable,
    // and a list must not be longer or shorter than its count.
    zklaim_wrap_payload_ctx second = {};
    for (int state = 0; state < 5; ++state) {
        SCOPED_TRACE(state);
        ctx.num_of_payloads = state == 1 || state == 3 ? 1 : state == 4 ? 2 : 0;
        ctx.pl_ctx_head = state >= 2 ? &payload : nullptr;
        payload.next = state == 3 ? &second : nullptr;
        unsigned char original[sizeof(ctx)];
        memcpy(original, &ctx, sizeof(ctx));
        for (size_t i = 0; i < 2; ++i) {
            const unsigned char *key = i == 0 ? keys.pk : keys.vk;
            const size_t key_size = i == 0 ? keys.pk_size : keys.vk_size;
            EXPECT_EQ(ZKLAIM_ERROR, operations[i](&ctx, key, key_size, zklaim_test_nonce));
            EXPECT_EQ(0, memcmp(original, &ctx, sizeof(ctx)));
        }
    }
}

TEST(zklaim, proving_rejects_keys_for_other_circuits_without_changing_context) {
    std::unique_ptr<zklaim_ctx, decltype(&zklaim_ctx_free)> ctx(
        zklaim_context_new(), zklaim_ctx_free);
    ASSERT_NE(nullptr, ctx);
    zklaim_payload pl = {};
    for (auto &op : pl.data_op) op = zklaim_noop;
    zklaim_add_pl(ctx.get(), pl);
    zklaim_add_pl(ctx.get(), pl);
    zklaim_hash_ctx(ctx.get());
    const auto &one = zklaim_keys_for(1);
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_proof_generate(ctx.get(), one.pk, one.pk_size, zklaim_test_nonce));
    EXPECT_EQ(nullptr, ctx->proof);
    EXPECT_EQ(0u, ctx->proof_size);
}

static int null_argument_result() {
    zklaim_ctx ctx = {};
    zklaim_wrap_payload_ctx payload = {};
    ctx.pl_ctx_head = &payload;
    ctx.num_of_payloads = 1;
    unsigned char key = 0;
    if (zklaim_trusted_setup(1, NULL, NULL, NULL, NULL) != ZKLAIM_ERROR ||
        zklaim_proof_generate(NULL, &key, 1, zklaim_test_nonce) != ZKLAIM_ERROR ||
        zklaim_proof_generate(&ctx, NULL, 1, zklaim_test_nonce) != ZKLAIM_ERROR ||
        zklaim_proof_generate(&ctx, &key, 1, NULL) != ZKLAIM_ERROR ||
        zklaim_proof_verify(NULL, &key, 1, zklaim_test_nonce) != ZKLAIM_ERROR ||
        zklaim_proof_verify(&ctx, &key, 1, zklaim_test_nonce) != ZKLAIM_ERROR) return 1;
    ctx.proof = &key;
    ctx.proof_size = 1;
    if (zklaim_proof_verify(&ctx, NULL, 1, zklaim_test_nonce) != ZKLAIM_ERROR ||
        zklaim_proof_verify(&ctx, &key, 1, NULL) != ZKLAIM_ERROR) return 2;
    return 0;
}

TEST(zklaimDeathTest, setup_and_proving_reject_null_arguments) {
    ASSERT_EXIT(_exit(null_argument_result()), ::testing::ExitedWithCode(0), "");
}

TEST(DISABLED_zklaim, can_handle_mismatching_payloads) {
    // TODO
}

TEST(DISABLED_zklaim, detect_forged_signature) {
    // TODO
}

enum zklaim_test_forgery {
    forge_nothing,
    forge_value,
    forge_reference,
    forge_operation
};

/**
 * builds the circuit for a payload with attribute #0 = 15 and the public statement
 * "attribute #0 >= ref", fills in the honest witness and then tampers with it as a
 * malicious prover would
 *
 * @return whether the (possibly tampered) witness satisfies the circuit
 */
static bool zklaim_test_circuit_accepts(uint64_t ref, enum zklaim_test_forgery forgery) {
    typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;
    default_r1cs_ppzksnark_pp::init_public_params();

    zklaim_payload pl;
    memset(&pl, 0, sizeof(zklaim_payload));
    for (int i = 0; i < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; i++)
        pl.data_op[i] = zklaim_noop;
    pl.data_ref[0] = ref;
    pl.data_op[0] = zklaim_greater_or_eq;
    zklaim_set_attr(&pl, 15, 0);

    zklaim_ctx *ctx = zklaim_context_new();
    zklaim_add_pl(ctx, pl);
    zklaim_hash_ctx(ctx);

    protoboard<FieldT> pb;
    zklaim_gadget<FieldT> g(pb, ctx->num_of_payloads);
    g.generate_r1cs_constraints();

    g.generate_r1cs_witness(ctx, zklaim_test_nonce);

    switch (forgery) {
        case forge_value:
            // claim attribute #0 is 99 instead of the hashed (and signed) 15
            pb.val(g.data[0][0]) = FieldT(99);
            pb.val(g.plvars[0]) = FieldT(99);
            g.data_cgs[0][0]->generate_r1cs_witness();
            break;
        case forge_reference:
            // compare against 10 instead of the public reference value
            pb.val(g.refvals[0]) = FieldT(10);
            g.data_cgs[0][0]->generate_r1cs_witness();
            break;
        case forge_operation:
            // turn the public ">=" into "noop"
            for (int k = 0; k < 7; k++)
                pb.val(g.opsvals[k]) = FieldT::zero();
            pb.val(g.opsvals[6]) = FieldT::one();
            break;
        case forge_nothing:
            break;
    }

    bool res = pb.is_satisfied();
    zklaim_ctx_free(ctx);
    return res;
}

TEST(zklaim, detect_forged_values_in_circuit) {
    // honest witnesses: 15 >= 10 holds, 15 >= 18 does not
    ASSERT_TRUE(zklaim_test_circuit_accepts(10, forge_nothing));
    ASSERT_FALSE(zklaim_test_circuit_accepts(18, forge_nothing));

    // tampering with the witness must not make 15 >= 18 provable
    EXPECT_FALSE(zklaim_test_circuit_accepts(18, forge_value));
    EXPECT_FALSE(zklaim_test_circuit_accepts(18, forge_reference));
    EXPECT_FALSE(zklaim_test_circuit_accepts(18, forge_operation));
}

TEST(zklaim, witness_generation_does_not_print_private_values) {
    typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;
    default_r1cs_ppzksnark_pp::init_public_params();
    zklaim_payload pl = {};
    for (uint8_t i = 0; i < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; ++i) {
        pl.data_op[i] = zklaim_noop;
        ASSERT_EQ(ZKLAIM_OK, zklaim_set_attr(&pl, UINT64_C(0x123456789abcdef0) + i, i));
    }
    zklaim_ctx *ctx = zklaim_context_new();
    ASSERT_NE(nullptr, ctx);
    zklaim_add_pl(ctx, pl);
    zklaim_hash_ctx(ctx);
    protoboard<FieldT> pb;
    zklaim_gadget<FieldT> g(pb, ctx->num_of_payloads);
    g.generate_r1cs_constraints();

    // Use the gadget directly to exercise its witness diagnostics.
    ::testing::internal::CaptureStdout();
    ::testing::internal::CaptureStderr();
    g.generate_r1cs_witness(ctx, zklaim_test_nonce);
    const std::string output = ::testing::internal::GetCapturedStdout();
    const std::string errors = ::testing::internal::GetCapturedStderr();
    EXPECT_TRUE(output.empty());
    EXPECT_TRUE(errors.empty());
    EXPECT_TRUE(pb.is_satisfied());
    // Only the attributes are packed for comparisons; the salt is only hashed.
    ASSERT_EQ(static_cast<size_t>(ZKLAIM_MAX_PAYLOAD_ATTRIBUTES), g.plvars.size());
    EXPECT_EQ(FieldT(UINT64_C(0x123456789abcdef0) + 4, true), pb.val(g.plvars[4]));
    zklaim_ctx_free(ctx);
}

TEST(zklaim, circuit_size_depends_only_on_payload_count) {
    typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;
    default_r1cs_ppzksnark_pp::init_public_params();
    protoboard<FieldT> first, second;
    zklaim_gadget<FieldT> a(first, 2), b(second, 2);
    a.generate_r1cs_constraints();
    b.generate_r1cs_constraints();
    EXPECT_TRUE(first.get_constraint_system() == second.get_constraint_system());
    // 2 x 1280 bits of hashes, references and operations plus a 256-bit nonce.
    EXPECT_EQ((2 * 1280 + 256 + FieldT::capacity() - 1) / FieldT::capacity(), first.num_inputs());
}

TEST(DISABLED_zklaim, rejects_invalid_proof) {
    // TODO
}


TEST(zklaim, preimage_and_salt_get_cleared) {
    zklaim_payload pl;
    memset(&pl, 0, sizeof(zklaim_payload));
    pl.data_ref[0] = 18;
    pl.data_op[0] = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data_ref[1] = 0;
    pl.data_op[1] = zklaim_eq;
    pl.data_ref[2] = 0;
    pl.data_op[2] = zklaim_eq;
    pl.data_ref[3] = 0;
    pl.data_op[3] = zklaim_eq;
    pl.data_ref[4] = 600;
    pl.data_op[4] = zklaim_less;
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

    for (unsigned char byte : ctx->pl_ctx_head->pl.salt) {
        ASSERT_EQ(0, byte);
    }

    for (unsigned char byte : ctx->pl_ctx_head->pl.pre) {
        ASSERT_EQ(0, byte);
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
    pl.data_ref[0] = 18;
    pl.data_op[0] = (enum zklaim_op) (zklaim_greater | zklaim_eq);
    pl.data_ref[1] = 0;
    pl.data_op[1] = zklaim_eq;
    pl.data_ref[2] = 0;
    pl.data_op[2] = zklaim_eq;
    pl.data_ref[3] = 0;
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

    zklaim_predicate expected[2] = {};
    memcpy(expected[0].data_ref, pl.data_ref, sizeof(pl.data_ref));
    memcpy(expected[0].data_op, pl.data_op, sizeof(pl.data_op));
    memcpy(expected[1].data_ref, pl2.data_ref, sizeof(pl2.data_ref));
    memcpy(expected[1].data_op, pl2.data_op, sizeof(pl2.data_op));

    zklaim_hash_ctx(ctx);

    // The issuer's setup for two-payload credentials, reused for every credential.
    const auto &keys = zklaim_keys_for(2);

    ASSERT_FALSE(zklaim_ctx_sign(ctx, priv));

    unsigned char* ctx_issuer;

    size_t len = zklaim_ctx_serialize_credential(ctx, &ctx_issuer);

    zklaim_ctx* ctx_prover = zklaim_context_new();
    ASSERT_FALSE(zklaim_ctx_deserialize(ctx_prover, ctx_issuer, len));

    int res = zklaim_ctx_verify(ctx_prover, pubbuf, keys.vk, keys.vk_size, expected, 2,
                                zklaim_test_nonce);
    ASSERT_EQ(ZKLAIM_INVALID_PROOF, res);

    ASSERT_FALSE(zklaim_proof_generate(ctx_prover, keys.pk, keys.pk_size, zklaim_test_nonce));

    zklaim_clear_pres(ctx_prover);

    unsigned char *ctx_prover_buf;
    len = zklaim_ctx_serialize(ctx_prover, &ctx_prover_buf);

    zklaim_ctx* ctx_verifier = zklaim_context_new();

    ASSERT_FALSE(zklaim_ctx_deserialize(ctx_verifier, ctx_prover_buf, len));
    res = zklaim_ctx_verify(ctx_verifier, pubbuf, keys.vk, keys.vk_size, expected, 2,
                            zklaim_test_nonce);
    ASSERT_FALSE(res);
    free(pubbuf);
}

