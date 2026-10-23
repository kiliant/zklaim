#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <cstddef>
#include <cstring>
#include <memory>
#include <vector>
#include <openssl/sha.h>

extern "C" {
#include <zklaim/zklaim.h>
}

namespace {

using context_ptr = std::unique_ptr<zklaim_ctx, decltype(&zklaim_ctx_free)>;

void rehash_header(std::vector<unsigned char> &blob) {
    SHA256(blob.data(), offsetof(zklaim_header, hash),
           blob.data() + offsetof(zklaim_header, hash));
}

std::vector<unsigned char> context_blob(size_t count = 2) {
    zklaim_header header = {};
    header.num_of_payloads = htonl(count);
    header.size_of_vk = htonl(3);
    header.size_of_sig = htonl(64);
    header.size_of_proof = htonl(2);
    memset(header.pub_key, 0xa5, sizeof(header.pub_key));
    std::vector<unsigned char> blob(sizeof(header) + count * sizeof(zklaim_payload) + 3 + 64 + 2);
    memcpy(blob.data(), &header, sizeof(header));
    for (size_t i = 0; i < count; ++i) {
        zklaim_payload pl = {};
        pl.data_ref[0] = i;
        for (auto &op : pl.data_op) op = zklaim_noop;
        memcpy(blob.data() + sizeof(header) + i * sizeof(pl), &pl, sizeof(pl));
    }
    memset(blob.data() + sizeof(header) + count * sizeof(zklaim_payload), 0x5a, 3 + 64 + 2);
    rehash_header(blob);
    return blob;
}

void expect_rejected_unchanged(unsigned char *data, size_t len) {
    zklaim_ctx ctx = {};
    memset(ctx.pub_key, 0xa5, sizeof(ctx.pub_key));
    memset(ctx.signature, 0x5a, sizeof(ctx.signature));
    unsigned char original[sizeof(ctx)];
    memcpy(original, &ctx, sizeof(ctx));
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_deserialize(&ctx, data, len));
    EXPECT_EQ(0, memcmp(original, &ctx, sizeof(ctx)));
}

} // namespace

TEST(zklaim_deserialize, round_trip_preserves_all_sections_and_payload_order) {
    auto blob = context_blob();
    context_ptr ctx(zklaim_context_new(), zklaim_ctx_free);
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_deserialize(ctx.get(), blob.data(), blob.size()));
    EXPECT_EQ(2u, ctx->num_of_payloads);
    ASSERT_NE(nullptr, ctx->pl_ctx_head);
    EXPECT_EQ(0u, ctx->pl_ctx_head->pl.data_ref[0]);
    ASSERT_NE(nullptr, ctx->pl_ctx_head->next);
    EXPECT_EQ(1u, ctx->pl_ctx_head->next->pl.data_ref[0]);
    EXPECT_EQ(nullptr, ctx->pl_ctx_head->next->next);
    unsigned char *serialized = nullptr;
    const size_t len = zklaim_ctx_serialize(ctx.get(), &serialized);
    std::unique_ptr<unsigned char, decltype(&free)> storage(serialized, free);
    ASSERT_EQ(blob.size(), len);
    EXPECT_EQ(0, memcmp(blob.data(), serialized, len));
}

TEST(zklaim_deserialize, rejects_every_truncation_without_changing_destination) {
    const auto blob = context_blob();
    for (size_t len = 0; len < blob.size(); ++len) {
        SCOPED_TRACE(len);
        // An exact-size allocation lets ASan detect reads past the supplied data.
        std::vector<unsigned char> truncated(blob.begin(), blob.begin() + len);
        expect_rejected_unchanged(truncated.data(), len);
    }
    auto extended = blob;
    extended.push_back(0);
    expect_rejected_unchanged(extended.data(), extended.size());
    expect_rejected_unchanged(nullptr, blob.size());
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_deserialize(nullptr, extended.data(), extended.size()));
}

TEST(zklaim_deserialize, detects_corruption_in_every_header_byte) {
    const auto valid = context_blob();
    for (size_t pos = 0; pos < sizeof(zklaim_header); ++pos) {
        SCOPED_TRACE(pos);
        auto corrupted = valid;
        corrupted[pos] ^= 1;
        expect_rejected_unchanged(corrupted.data(), corrupted.size());
    }
}

TEST(zklaim_deserialize, rejects_inconsistent_and_overflowing_section_sizes) {
    const auto valid = context_blob();
    const size_t offsets[] = {
        offsetof(zklaim_header, num_of_payloads),
        offsetof(zklaim_header, size_of_vk),
        offsetof(zklaim_header, size_of_sig),
        offsetof(zklaim_header, size_of_proof)
    };
    for (size_t offset : offsets) {
        for (uint32_t value : {UINT32_C(0), UINT32_C(1), UINT32_MAX}) {
            SCOPED_TRACE(offset);
            SCOPED_TRACE(value);
            auto blob = valid;
            const uint32_t encoded = htonl(value);
            memcpy(blob.data() + offset, &encoded, sizeof(encoded));
            rehash_header(blob);
            expect_rejected_unchanged(blob.data(), blob.size());
        }
    }
    // These section sizes wrap a naive 32-bit total back to the actual length.
    auto wrapped = valid;
    const uint32_t vk_size = htonl(UINT32_MAX);
    const uint32_t proof_size = htonl(6);
    memcpy(wrapped.data() + offsetof(zklaim_header, size_of_vk), &vk_size, sizeof(vk_size));
    memcpy(wrapped.data() + offsetof(zklaim_header, size_of_proof), &proof_size, sizeof(proof_size));
    rehash_header(wrapped);
    expect_rejected_unchanged(wrapped.data(), wrapped.size());
}

TEST(zklaim_deserialize, rejects_nonempty_contexts_without_changing_them) {
    auto blob = context_blob();
    unsigned char byte = 0;
    zklaim_wrap_payload_ctx payload = {};
    for (int field = 0; field < 8; ++field) {
        SCOPED_TRACE(field);
        zklaim_ctx ctx = {};
        switch (field) {
            case 0: ctx.num_of_payloads = 1; break;
            case 1: ctx.pl_ctx_head = &payload; break;
            case 2: ctx.pk_size = 1; break;
            case 3: ctx.pk = &byte; break;
            case 4: ctx.vk_size = 1; break;
            case 5: ctx.vk = &byte; break;
            case 6: ctx.proof_size = 1; break;
            case 7: ctx.proof = &byte; break;
        }
        unsigned char original[sizeof(ctx)];
        memcpy(original, &ctx, sizeof(ctx));
        EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_deserialize(&ctx, blob.data(), blob.size()));
        EXPECT_EQ(0, memcmp(original, &ctx, sizeof(ctx)));
    }
}

TEST(zklaim_deserialize, accepts_unaligned_input) {
    const auto blob = context_blob();
    std::vector<unsigned char> unaligned(blob.size() + 1);
    memcpy(unaligned.data() + 1, blob.data(), blob.size());
    context_ptr ctx(zklaim_context_new(), zklaim_ctx_free);
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_deserialize(ctx.get(), unaligned.data() + 1, blob.size()));
    EXPECT_EQ(2u, ctx->num_of_payloads);
}

TEST(zklaim_deserialize, accepts_empty_sections_and_many_payloads) {
    zklaim_header header = {};
    header.size_of_sig = htonl(64);
    std::vector<unsigned char> empty(sizeof(header) + 64);
    memcpy(empty.data(), &header, sizeof(header));
    rehash_header(empty);
    context_ptr ctx(zklaim_context_new(), zklaim_ctx_free);
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_deserialize(ctx.get(), empty.data(), empty.size()));
    EXPECT_EQ(0u, ctx->num_of_payloads);
    EXPECT_EQ(nullptr, ctx->pl_ctx_head);
    EXPECT_EQ(nullptr, ctx->vk);
    EXPECT_EQ(nullptr, ctx->proof);
    unsigned char *serialized = nullptr;
    const size_t len = zklaim_ctx_serialize(ctx.get(), &serialized);
    std::unique_ptr<unsigned char, decltype(&free)> storage(serialized, free);
    ASSERT_EQ(empty.size(), len);
    EXPECT_EQ(0, memcmp(empty.data(), serialized, len));

    auto large = context_blob(10000);
    context_ptr many(zklaim_context_new(), zklaim_ctx_free);
    ASSERT_NE(nullptr, many);
    ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_deserialize(many.get(), large.data(), large.size()));
    size_t i = 0;
    for (auto *node = many->pl_ctx_head; node; node = node->next, ++i) {
        EXPECT_EQ(i, node->pl.data_ref[0]);
    }
    EXPECT_EQ(10000u, i);
}
