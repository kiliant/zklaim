#include <gtest/gtest.h>
#include <cstring>
#include <memory>
#include <vector>
#include <openssl/sha.h>

extern "C" {
#include <zklaim/zklaim.h>
#include <zklaim/zklaim_wire.h>
}

namespace {
using context_ptr = std::unique_ptr<zklaim_ctx, decltype(&zklaim_ctx_free)>;

void rehash_header(std::vector<unsigned char> &blob) {
    SHA256(blob.data(), 56, blob.data() + 56);
}

std::vector<unsigned char> context_blob(size_t count = 2, bool credential = false) {
    const size_t record = credential ? 126 : 77;
    std::vector<unsigned char> blob(88 + count * record + 3 + 64 + 2);
    memcpy(blob.data(), "ZKLM", 4);
    blob[5] = 1;
    blob[6] = credential ? 1 : 2;
    blob[7] = zklaim_wire_curve();
    zklaim_store_u32(blob.data() + 8, static_cast<uint32_t>(count));
    zklaim_store_u32(blob.data() + 12, 3);
    zklaim_store_u32(blob.data() + 16, 2);
    memset(blob.data() + 24, 0xa5, 32);
    for (size_t i = 0; i < count; ++i) {
        unsigned char *pl = blob.data() + 88 + i * record;
        zklaim_store_u64(pl, i);
        memset(pl + 40, zklaim_noop, 5);
        if (credential) {
            zklaim_store_u64(pl + 78, UINT64_C(0x0102030405060708));
            zklaim_store_u64(pl + 118, UINT64_C(0xfedcba9876543210));
        }
    }
    memset(blob.data() + 88 + count * record, 0x5a, 3 + 64 + 2);
    rehash_header(blob);
    return blob;
}

void expect_rejected_unchanged(unsigned char *data, size_t len) {
    context_ptr ctx(zklaim_context_new(), zklaim_ctx_free);
    ASSERT_NE(nullptr, ctx);
    memset(ctx->pub_key, 0xa5, sizeof(ctx->pub_key));
    memset(ctx->signature, 0x5a, sizeof(ctx->signature));
    unsigned char original[sizeof(*ctx)];
    memcpy(original, ctx.get(), sizeof(*ctx));
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_deserialize(ctx.get(), data, len));
    EXPECT_EQ(0, memcmp(original, ctx.get(), sizeof(*ctx)));
}

std::vector<unsigned char> wire_hex(const char *hex) {
    std::vector<unsigned char> bytes;
    while (*hex) {
        auto nibble = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        bytes.push_back(static_cast<unsigned char>((nibble(hex[0]) << 4) | nibble(hex[1])));
        hex += 2;
    }
    return bytes;
}
} // namespace

TEST(zklaim_deserialize, round_trip_preserves_all_sections_and_payload_order) {
    for (bool credential : {false, true}) {
        auto blob = context_blob(2, credential);
        context_ptr ctx(zklaim_context_new(), zklaim_ctx_free);
        ASSERT_NE(nullptr, ctx);
        ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_deserialize(ctx.get(), blob.data(), blob.size()));
        EXPECT_EQ(2u, ctx->num_of_payloads);
        ASSERT_NE(nullptr, ctx->pl_ctx_head);
        EXPECT_EQ(0u, ctx->pl_ctx_head->pl.data_ref[0]);
        ASSERT_NE(nullptr, ctx->pl_ctx_head->next);
        EXPECT_EQ(1u, ctx->pl_ctx_head->next->pl.data_ref[0]);
        EXPECT_EQ(nullptr, ctx->pl_ctx_head->next->next);
        EXPECT_EQ(credential ? 0 : 1, ctx->pl_ctx_head->pl.priv);
        uint64_t attr;
        ASSERT_EQ(ZKLAIM_OK, zklaim_get_attr(&ctx->pl_ctx_head->pl, 0, &attr));
        EXPECT_EQ(credential ? UINT64_C(0x0102030405060708) : 0, attr);
        EXPECT_EQ(credential ? UINT64_C(0xfedcba9876543210) : 0, ctx->pl_ctx_head->pl.salt);
        unsigned char *serialized = nullptr;
        const size_t len = credential ? zklaim_ctx_serialize_credential(ctx.get(), &serialized) :
                                        zklaim_ctx_serialize(ctx.get(), &serialized);
        std::unique_ptr<unsigned char, decltype(&free)> storage(serialized, free);
        ASSERT_EQ(blob.size(), len);
        EXPECT_EQ(0, memcmp(blob.data(), serialized, len));
    }
}

TEST(zklaim_deserialize, matches_independent_big_endian_golden_frame) {
    if (zklaim_wire_curve() != 1) GTEST_SKIP() << "golden frame selects ALT_BN128";
    // Generated independently with Python struct.pack('>5Q') and hashlib.sha256.
    auto blob = wire_hex(
        "5a4b4c4d0001020100000001000000000000000000000000000102030405060708090a0b0c0d0e0f1011121314151617"
        "18191a1b1c1d1e1f2f15bb20ee1017d645ba1de932d519f704e6ef397f0b384e5d47bf05cde6590d0102030405060708"
        "ffffffffffffffff00000000000000008000000000000000000000000000002a0103020a63202122232425262728292a"
        "2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a"
        "5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f");
    context_ptr ctx(zklaim_context_new(), zklaim_ctx_free);
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_deserialize(ctx.get(), blob.data(), blob.size()));
    const uint64_t expected[] = {UINT64_C(0x0102030405060708), UINT64_MAX, 0, UINT64_C(0x8000000000000000), 42};
    for (size_t i = 0; i < 5; ++i) EXPECT_EQ(expected[i], ctx->pl_ctx_head->pl.data_ref[i]);
    unsigned char *out = nullptr;
    const size_t len = zklaim_ctx_serialize(ctx.get(), &out);
    std::unique_ptr<unsigned char, decltype(&free)> storage(out, free);
    ASSERT_EQ(blob.size(), len);
    EXPECT_EQ(0, memcmp(blob.data(), out, len));
}

TEST(zklaim_deserialize, presentations_never_copy_witnesses_or_struct_padding) {
    context_ptr ctx(zklaim_context_new(), zklaim_ctx_free);
    ASSERT_NE(nullptr, ctx);
    zklaim_payload pl;
    memset(&pl, 0xa5, sizeof(pl)); // Poison witness storage and all struct padding.
    for (size_t i = 0; i < 5; ++i) { pl.data_ref[i] = i; pl.data_op[i] = zklaim_noop; }
    memset(pl.hash, 0x5a, 32);
    pl.priv = 0;
    zklaim_add_pl(ctx.get(), pl);
    unsigned char *first = nullptr, *second = nullptr;
    const size_t size = zklaim_ctx_serialize(ctx.get(), &first);
    std::unique_ptr<unsigned char, decltype(&free)> first_storage(first, free);
    ASSERT_EQ(88u + 77u + 64u, size);
    ASSERT_NE(nullptr, first);
    zklaim_clear_pres(ctx.get());
    EXPECT_EQ(size, zklaim_ctx_serialize(ctx.get(), &second));
    std::unique_ptr<unsigned char, decltype(&free)> second_storage(second, free);
    ASSERT_NE(nullptr, second);
    EXPECT_EQ(0, memcmp(first, second, size));
    context_ptr received(zklaim_context_new(), zklaim_ctx_free);
    ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_deserialize(received.get(), first, size));
    EXPECT_EQ(1, received->pl_ctx_head->pl.priv);
    EXPECT_EQ(0u, received->pl_ctx_head->pl.salt);
    unsigned char zero[48] = {};
    EXPECT_EQ(0, memcmp(zero, received->pl_ctx_head->pl.pre, sizeof(zero)));
}

TEST(zklaim_deserialize, rejects_every_truncation_without_changing_destination) {
    for (bool credential : {false, true}) {
        const auto blob = context_blob(2, credential);
        for (size_t len = 0; len < blob.size(); ++len) {
            SCOPED_TRACE(len);
            std::vector<unsigned char> truncated(blob.begin(), blob.begin() + len);
            expect_rejected_unchanged(truncated.data(), len);
        }
        auto extended = blob;
        extended.push_back(0);
        expect_rejected_unchanged(extended.data(), extended.size());
    }
    auto blob = context_blob();
    expect_rejected_unchanged(nullptr, blob.size());
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_deserialize(nullptr, blob.data(), blob.size()));
}

TEST(zklaim_deserialize, detects_corruption_in_every_header_byte) {
    const auto valid = context_blob();
    for (size_t pos = 0; pos < 88; ++pos) {
        SCOPED_TRACE(pos);
        auto corrupted = valid;
        corrupted[pos] ^= 1;
        expect_rejected_unchanged(corrupted.data(), corrupted.size());
    }
}

TEST(zklaim_deserialize, rejects_unknown_formats_and_noncanonical_payloads) {
    for (size_t offset : {0u, 4u, 5u, 6u, 7u, 20u}) {
        auto blob = context_blob();
        blob[offset] = 0xff;
        rehash_header(blob);
        expect_rejected_unchanged(blob.data(), blob.size());
    }
    auto invalid_op = context_blob();
    invalid_op[88 + 40] = 0;
    expect_rejected_unchanged(invalid_op.data(), invalid_op.size());
    auto invalid_flag = context_blob(2, true);
    invalid_flag[88 + 77] = 2;
    expect_rejected_unchanged(invalid_flag.data(), invalid_flag.size());
    auto hidden_witness = context_blob(2, true);
    hidden_witness[88 + 77] = 1; // A hidden credential must contain zero witness bytes.
    expect_rejected_unchanged(hidden_witness.data(), hidden_witness.size());
    std::vector<unsigned char> legacy(80 + 2 * 160 + 64);
    expect_rejected_unchanged(legacy.data(), legacy.size());
}

TEST(zklaim_deserialize, rejects_inconsistent_and_overflowing_section_sizes) {
    for (size_t offset : {8u, 12u, 16u}) {
        for (uint32_t value : {UINT32_C(0), UINT32_C(1), UINT32_MAX}) {
            auto blob = context_blob();
            zklaim_store_u32(blob.data() + offset, value);
            rehash_header(blob);
            expect_rejected_unchanged(blob.data(), blob.size());
        }
    }
    auto wrapped = context_blob();
    zklaim_store_u32(wrapped.data() + 12, UINT32_MAX);
    zklaim_store_u32(wrapped.data() + 16, 6);
    rehash_header(wrapped);
    expect_rejected_unchanged(wrapped.data(), wrapped.size());
}

TEST(zklaim_deserialize, rejects_nonempty_contexts_without_changing_them) {
    auto blob = context_blob();
    unsigned char byte = 0;
    zklaim_wrap_payload_ctx payload = {};
    for (int field = 0; field < 8; ++field) {
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
    auto empty = context_blob(0);
    empty.resize(88 + 64);
    zklaim_store_u32(empty.data() + 12, 0);
    zklaim_store_u32(empty.data() + 16, 0);
    rehash_header(empty);
    context_ptr ctx(zklaim_context_new(), zklaim_ctx_free);
    ASSERT_NE(nullptr, ctx);
    ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_deserialize(ctx.get(), empty.data(), empty.size()));
    EXPECT_EQ(nullptr, ctx->pl_ctx_head);
    EXPECT_EQ(nullptr, ctx->vk);
    EXPECT_EQ(nullptr, ctx->proof);
    auto large = context_blob(10000);
    context_ptr many(zklaim_context_new(), zklaim_ctx_free);
    ASSERT_NE(nullptr, many);
    ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_deserialize(many.get(), large.data(), large.size()));
    size_t i = 0;
    for (auto *node = many->pl_ctx_head; node; node = node->next, ++i) EXPECT_EQ(i, node->pl.data_ref[0]);
    EXPECT_EQ(10000u, i);
}

TEST(zklaim_deserialize, attribute_access_uses_fixed_big_endian_words) {
    zklaim_payload pl = {};
    const uint64_t values[] = {UINT64_C(0x0102030405060708), UINT64_MAX, 0,
                              UINT64_C(0x8000000000000000), 42};
    for (uint8_t i = 0; i < 5; ++i) ASSERT_EQ(ZKLAIM_OK, zklaim_set_attr(&pl, values[i], i));
    const auto expected = wire_hex(
        "0102030405060708ffffffffffffffff00000000000000008000000000000000000000000000002a0000000000000000");
    ASSERT_EQ(sizeof(pl.pre), expected.size());
    EXPECT_EQ(0, memcmp(expected.data(), pl.pre, expected.size()));
    for (uint8_t i = 0; i < 5; ++i) {
        uint64_t value = 0;
        ASSERT_EQ(ZKLAIM_OK, zklaim_get_attr(&pl, i, &value));
        EXPECT_EQ(values[i], value);
    }
    uint64_t unchanged = 42;
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_get_attr(&pl, 5, &unchanged));
    EXPECT_EQ(42u, unchanged);
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_get_attr(nullptr, 0, &unchanged));
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_get_attr(&pl, 0, nullptr));
}

TEST(zklaim_deserialize, serializers_reject_inconsistent_storage_without_output) {
    zklaim_wrap_payload_ctx payload = {};
    for (auto &op : payload.pl.data_op) op = zklaim_noop;
    zklaim_ctx ctx = {};
    unsigned char byte = 0;
    const auto serializers = {zklaim_ctx_serialize, zklaim_ctx_serialize_credential};
    for (auto serialize : serializers) {
        unsigned char *out = nullptr;
        EXPECT_EQ(0u, serialize(nullptr, &out));
        EXPECT_EQ(nullptr, out);
        EXPECT_EQ(0u, serialize(&ctx, nullptr));
        ctx.num_of_payloads = 1;
        EXPECT_EQ(0u, serialize(&ctx, &out));
        EXPECT_EQ(nullptr, out);
        ctx.pl_ctx_head = &payload;
        ctx.num_of_payloads = 0;
        EXPECT_EQ(0u, serialize(&ctx, &out));
        EXPECT_EQ(nullptr, out);
        ctx.num_of_payloads = 1;
        ctx.vk_size = 1;
        EXPECT_EQ(0u, serialize(&ctx, &out));
        ctx.vk_size = 0;
        ctx.proof_size = 1;
        EXPECT_EQ(0u, serialize(&ctx, &out));
        ctx.proof_size = 0;
        ctx.num_of_payloads = UINT32_MAX;
        EXPECT_EQ(0u, serialize(&ctx, &out));
        ctx.num_of_payloads = 1;
        payload.pl.data_op[0] = static_cast<zklaim_op>(0);
        EXPECT_EQ(0u, serialize(&ctx, &out));
        EXPECT_EQ(nullptr, out);
        payload.pl.data_op[0] = zklaim_noop;
#if SIZE_MAX > UINT32_MAX
        ctx.vk = &byte;
        ctx.vk_size = static_cast<size_t>(UINT32_MAX) + 1;
        EXPECT_EQ(0u, serialize(&ctx, &out));
        ctx.vk = nullptr;
        ctx.vk_size = 0;
#endif
        ctx.pl_ctx_head = nullptr;
        ctx.num_of_payloads = 0;
    }
}
