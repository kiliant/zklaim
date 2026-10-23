#include <gtest/gtest.h>
#include <memory>
#include <sstream>
#include <vector>

extern "C" {
#include <zklaim/zklaim.h>
}

TEST(zklaim_snark_parsing, rejects_invalid_artifacts_at_the_c_boundary) {
    std::unique_ptr<zklaim_ctx, decltype(&zklaim_ctx_free)> ctx(
        zklaim_context_new(), zklaim_ctx_free);
    ASSERT_NE(nullptr, ctx);
    zklaim_payload pl = {};
    for (auto &op : pl.data_op) op = zklaim_noop;
    zklaim_add_pl(ctx.get(), pl);
    zklaim_hash_ctx(ctx.get());
    const auto &keys = zklaim_keys_for(1);
    ASSERT_NE(nullptr, keys.pk);
    ASSERT_EQ(ZKLAIM_OK, zklaim_proof_generate(ctx.get(), keys.pk, keys.pk_size, zklaim_test_nonce));
    ASSERT_EQ(ZKLAIM_OK, zklaim_proof_verify(ctx.get(), keys.vk, keys.vk_size, zklaim_test_nonce));

    // Every failure must preserve the original proof.
    const auto proof = ctx->proof;
    const auto attempt = [&](int artifact, const unsigned char *bytes, size_t size) {
        if (artifact == 0) return zklaim_proof_generate(ctx.get(), bytes, size, zklaim_test_nonce);
        if (artifact == 1) return zklaim_proof_verify(ctx.get(), bytes, size, zklaim_test_nonce);
        zklaim_ctx view = *ctx; // Non-owning view with a replaced proof.
        view.proof = const_cast<unsigned char *>(bytes);
        view.proof_size = size;
        return zklaim_proof_verify(&view, keys.vk, keys.vk_size, zklaim_test_nonce);
    };
    for (int artifact = 0; artifact < 3; ++artifact) {
        SCOPED_TRACE(artifact);
        const unsigned char *bytes = artifact == 0 ? keys.pk : artifact == 1 ? keys.vk : ctx->proof;
        const size_t size = artifact == 0 ? keys.pk_size : artifact == 1 ? keys.vk_size : ctx->proof_size;
        const size_t lengths[] = {0, 1, size / 2, size - 1};
        for (size_t length : lengths) {
            SCOPED_TRACE(length);
            EXPECT_EQ(ZKLAIM_ERROR, attempt(artifact, bytes, length));
            EXPECT_EQ(proof, ctx->proof);
        }

        EXPECT_EQ(ZKLAIM_ERROR, attempt(artifact, nullptr, size));
        EXPECT_EQ(proof, ctx->proof);

        std::vector<unsigned char> trailing(bytes, bytes + size);
        trailing.push_back(0);
        EXPECT_EQ(ZKLAIM_ERROR, attempt(artifact, trailing.data(), trailing.size()));
        EXPECT_EQ(proof, ctx->proof);
    }

    // libff's decimal bigint parser otherwise asserts or overwrites fixed limbs.
    for (const std::string &bad : {std::string("garbage "), std::string(1000, '9') + " "}) {
        EXPECT_EQ(ZKLAIM_ERROR, attempt(1, reinterpret_cast<const unsigned char *>(bad.data()), bad.size()));
    }

    // A valid verification-key prefix followed by a huge sparse-vector count
    // must not allocate based on an untrusted native integer.
    using pp = libsnark::default_r1cs_ppzksnark_pp;
    libsnark::r1cs_gg_ppzksnark_verification_key<pp> vk;
    std::stringstream original(std::string(reinterpret_cast<char *>(keys.vk), keys.vk_size));
    original >> vk;
    ASSERT_TRUE(original);
    std::stringstream oversized;
    oversized << vk.alpha_g1_beta_g2 << OUTPUT_NEWLINE
              << vk.gamma_g2 << OUTPUT_NEWLINE
              << vk.delta_g2 << OUTPUT_NEWLINE
              << vk.gamma_ABC_g1.first << OUTPUT_NEWLINE
              << vk.gamma_ABC_g1.rest.domain_size() << '\n'
              << SIZE_MAX << '\n';
    const std::string bad_count = oversized.str();
    EXPECT_EQ(ZKLAIM_ERROR, attempt(1, reinterpret_cast<const unsigned char *>(bad_count.data()), bad_count.size()));

    // Stream-readable sparse vectors must also have matching, ordered entries.
    vk.gamma_ABC_g1.rest.indices.clear();
    std::stringstream mismatched;
    mismatched << vk;
    const std::string bad_vector = mismatched.str();
    EXPECT_EQ(ZKLAIM_ERROR, attempt(1, reinterpret_cast<const unsigned char *>(bad_vector.data()), bad_vector.size()));
    EXPECT_EQ(ZKLAIM_OK, zklaim_proof_verify(ctx.get(), keys.vk, keys.vk_size, zklaim_test_nonce));
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_proof_verify(nullptr, keys.vk, keys.vk_size, zklaim_test_nonce));
}

TEST(zklaim_snark_parsing, rejects_canonical_proving_keys_with_inconsistent_vectors) {
    std::unique_ptr<zklaim_ctx, decltype(&zklaim_ctx_free)> ctx(
        zklaim_context_new(), zklaim_ctx_free);
    ASSERT_NE(nullptr, ctx);
    zklaim_payload pl = {};
    for (auto &op : pl.data_op) op = zklaim_noop;
    zklaim_add_pl(ctx.get(), pl);
    zklaim_hash_ctx(ctx.get());
    const auto &keys = zklaim_keys_for(1);
    ASSERT_NE(nullptr, keys.pk);

    // These re-encode canonically, so only the circuit check stops the prover
    // from indexing past the end of a vector.
    using pp = libsnark::default_r1cs_ppzksnark_pp;
    libsnark::r1cs_gg_ppzksnark_proving_key<pp> parsed;
    std::stringstream original(std::string(reinterpret_cast<char *>(keys.pk), keys.pk_size));
    original >> parsed;
    ASSERT_TRUE(original);
    for (int corruption = 0; corruption < 5; ++corruption) {
        SCOPED_TRACE(corruption);
        auto pk = parsed;
        switch (corruption) {
            case 0: pk.A_query.pop_back(); break;
            case 1: pk.B_query.indices.pop_back(); break;
            case 2: pk.B_query.indices.back() = pk.B_query.domain_size(); break;
            case 3: pk.H_query.pop_back(); break;
            case 4: pk.L_query.pop_back(); break;
        }
        std::stringstream modified;
        modified << pk;
        const std::string bad = modified.str();
        EXPECT_EQ(ZKLAIM_ERROR, zklaim_proof_generate(ctx.get(), reinterpret_cast<const unsigned char *>(bad.data()),
                                                      bad.size(), zklaim_test_nonce));
        EXPECT_EQ(nullptr, ctx->proof);
    }
}
