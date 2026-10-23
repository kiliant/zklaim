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
    ASSERT_EQ(ZKLAIM_OK, zklaim_trusted_setup(ctx.get()));
    ASSERT_EQ(ZKLAIM_OK, zklaim_proof_generate(ctx.get()));
    ASSERT_EQ(ZKLAIM_OK, zklaim_proof_verify(ctx.get()));

    // Test non-owning views so every failure must preserve the original proof.
    zklaim_ctx view = *ctx;
    const auto proof = ctx->proof;
    for (int artifact = 0; artifact < 3; ++artifact) {
        SCOPED_TRACE(artifact);
        unsigned char *bytes = artifact == 0 ? ctx->pk : artifact == 1 ? ctx->vk : ctx->proof;
        const size_t size = artifact == 0 ? ctx->pk_size : artifact == 1 ? ctx->vk_size : ctx->proof_size;
        const size_t lengths[] = {0, 1, size / 2, size - 1};
        for (size_t length : lengths) {
            SCOPED_TRACE(length);
            view = *ctx;
            if (artifact == 0) view.pk_size = length;
            if (artifact == 1) view.vk_size = length;
            if (artifact == 2) view.proof_size = length;
            EXPECT_EQ(ZKLAIM_ERROR, artifact == 0 ? zklaim_proof_generate(&view) : zklaim_proof_verify(&view));
            EXPECT_EQ(proof, view.proof);
        }

        view = *ctx;
        if (artifact == 0) view.pk = nullptr;
        if (artifact == 1) view.vk = nullptr;
        if (artifact == 2) view.proof = nullptr;
        EXPECT_EQ(ZKLAIM_ERROR, artifact == 0 ? zklaim_proof_generate(&view) : zklaim_proof_verify(&view));

        std::vector<unsigned char> trailing(bytes, bytes + size);
        trailing.push_back(0);
        view = *ctx;
        if (artifact == 0) { view.pk = trailing.data(); view.pk_size = trailing.size(); }
        if (artifact == 1) { view.vk = trailing.data(); view.vk_size = trailing.size(); }
        if (artifact == 2) { view.proof = trailing.data(); view.proof_size = trailing.size(); }
        EXPECT_EQ(ZKLAIM_ERROR, artifact == 0 ? zklaim_proof_generate(&view) : zklaim_proof_verify(&view));
    }

    // libff's decimal bigint parser otherwise asserts or overwrites fixed limbs.
    for (const std::string &bad : {std::string("garbage "), std::string(1000, '9') + " "}) {
        view = *ctx;
        view.vk = reinterpret_cast<unsigned char *>(const_cast<char *>(bad.data()));
        view.vk_size = bad.size();
        EXPECT_EQ(ZKLAIM_ERROR, zklaim_proof_verify(&view));
    }

    // A valid verification-key prefix followed by a huge sparse-vector count
    // must not allocate based on an untrusted native integer.
    using pp = libsnark::default_r1cs_ppzksnark_pp;
    libsnark::r1cs_gg_ppzksnark_verification_key<pp> vk;
    std::stringstream original(std::string(reinterpret_cast<char *>(ctx->vk), ctx->vk_size));
    original >> vk;
    ASSERT_TRUE(original);
    std::stringstream oversized;
    oversized << vk.alpha_g1_beta_g2 << OUTPUT_NEWLINE
              << vk.gamma_g2 << OUTPUT_NEWLINE
              << vk.delta_g2 << OUTPUT_NEWLINE
              << vk.gamma_ABC_g1.first << OUTPUT_NEWLINE
              << vk.gamma_ABC_g1.rest.domain_size() << '\n'
              << SIZE_MAX << '\n';
    std::string bad_count = oversized.str();
    view = *ctx;
    view.vk = reinterpret_cast<unsigned char *>(&bad_count[0]);
    view.vk_size = bad_count.size();
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_proof_verify(&view));

    // Stream-readable sparse vectors must also have matching, ordered entries.
    vk.gamma_ABC_g1.rest.indices.clear();
    std::stringstream mismatched;
    mismatched << vk;
    std::string bad_vector = mismatched.str();
    view = *ctx;
    view.vk = reinterpret_cast<unsigned char *>(&bad_vector[0]);
    view.vk_size = bad_vector.size();
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_proof_verify(&view));
    EXPECT_EQ(ZKLAIM_OK, zklaim_proof_verify(ctx.get()));
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_proof_verify(nullptr));
    EXPECT_EQ(ZKLAIM_ERROR, libsnark_verify(nullptr));
}
