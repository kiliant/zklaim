#include <gtest/gtest.h>
#include <atomic>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

extern "C" {
#include <zklaim/zklaim.h>
}

namespace {

struct verifier_test_key {
    gcry_sexp_t value = nullptr;
    ~verifier_test_key() { gcry_sexp_release(value); }
};

class zklaim_verifier : public ::testing::Test {
protected:
    using ctx_ptr = std::unique_ptr<zklaim_ctx, decltype(&zklaim_ctx_free)>;
    static ctx_ptr issuer;
    static unsigned char trusted_key[32];
    static const zklaim_predicate policy[2];
    static std::vector<unsigned char> presentation;
    ctx_ptr received{nullptr, zklaim_ctx_free};

    static std::vector<unsigned char> serialize(zklaim_ctx *ctx, bool credential = false) {
        unsigned char *data = nullptr;
        const size_t len = credential ? zklaim_ctx_serialize_credential(ctx, &data) : zklaim_ctx_serialize(ctx, &data);
        std::unique_ptr<unsigned char, decltype(&free)> storage(data, free);
        if (len == 0 || data == nullptr) return {};
        return std::vector<unsigned char>(data, data + len);
    }

    void SetUp() override {
        received.reset(zklaim_context_new());
        ASSERT_NE(nullptr, received);
        ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_deserialize(received.get(), presentation.data(), presentation.size()));
    }

    static const zklaim_test_keys &keys() {
        return zklaim_keys_for(2);
    }

    static int verify_with(zklaim_ctx *ctx, const unsigned char *issuer_key,
                           const zklaim_predicate *expected, size_t count,
                           const unsigned char *nonce = zklaim_test_nonce) {
        return zklaim_ctx_verify(ctx, issuer_key, keys().vk, keys().vk_size, expected, count, nonce);
    }

    int verify() {
        return verify_with(received.get(), trusted_key, policy, 2);
    }

    // Issues a two-payload credential with the given attribute 0 and returns
    // its presentation, proved for the given nonce.
    static std::vector<unsigned char> present(gcry_sexp_t priv, const unsigned char issuer_key[32],
                                              uint64_t age, const unsigned char *nonce,
                                              ctx_ptr *witnesses = nullptr) {
        ctx_ptr ctx(zklaim_context_new(), zklaim_ctx_free);
        if (!ctx) return {};
        for (size_t i = 0; i < 2; ++i) {
            zklaim_payload pl = {};
            memcpy(pl.data_ref, policy[i].data_ref, sizeof(pl.data_ref));
            memcpy(pl.data_op, policy[i].data_op, sizeof(pl.data_op));
            if (zklaim_set_attr(&pl, age, 0) || zklaim_set_attr(&pl, 42, 1) ||
                zklaim_set_attr(&pl, 599, 4)) return {};
            zklaim_add_pl(ctx.get(), pl);
        }
        zklaim_hash_ctx(ctx.get());
        if (zklaim_ctx_sign(ctx.get(), priv) != ZKLAIM_OK || memcmp(ctx->pub_key, issuer_key, 32) != 0 ||
            zklaim_proof_generate(ctx.get(), keys().pk, keys().pk_size, nonce) != ZKLAIM_OK) return {};
        auto blob = serialize(ctx.get());
        if (witnesses) *witnesses = std::move(ctx);
        return blob;
    }

public:
    static void SetUpTestSuite() {
        verifier_test_key priv, pub;
        ASSERT_EQ(ZKLAIM_OK, zklaim_gen_pk(&priv.value));
        ASSERT_EQ(ZKLAIM_OK, zklaim_get_pub(priv.value, &pub.value));
        unsigned char *key = nullptr;
        size_t key_size = 0;
        ASSERT_EQ(ZKLAIM_OK, zklaim_pub2buf(pub.value, &key, &key_size));
        std::unique_ptr<unsigned char, decltype(&free)> key_storage(key, free);
        ASSERT_EQ(sizeof(trusted_key), key_size);
        memcpy(trusted_key, key, key_size);

        ASSERT_NE(nullptr, keys().pk);
        // Keep the issuer's witnesses for the weaker-predicate regression.
        presentation = present(priv.value, trusted_key, 23, zklaim_test_nonce, &issuer);
        ASSERT_FALSE(presentation.empty());
    }

    static void TearDownTestSuite() {
        issuer.reset();
        presentation.clear();
    }
};

zklaim_verifier::ctx_ptr zklaim_verifier::issuer(nullptr, zklaim_ctx_free);
unsigned char zklaim_verifier::trusted_key[32] = {};
std::vector<unsigned char> zklaim_verifier::presentation;
const zklaim_predicate zklaim_verifier::policy[2] = {
    {{18, 42, 0, 0, 0},
     {zklaim_greater_or_eq, zklaim_eq, zklaim_noop, zklaim_noop, zklaim_noop}},
    {{0, 0, 0, 0, 600},
     {zklaim_noop, zklaim_noop, zklaim_noop, zklaim_noop, zklaim_less}}
};

TEST_F(zklaim_verifier, accepts_trusted_issuer_and_exact_policy_without_mutation) {
    const auto before = serialize(received.get());
    ASSERT_EQ(ZKLAIM_OK, verify());
    EXPECT_EQ(before, serialize(received.get()));
    EXPECT_EQ(1, received->pl_ctx_head->pl.priv);
    EXPECT_EQ(1, received->pl_ctx_head->next->pl.priv);
}

TEST_F(zklaim_verifier, concurrent_verification_uses_initialized_curve_parameters) {
    std::atomic<int> failures{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&] {
            for (int j = 0; j < 10; ++j) {
                if (verify() != ZKLAIM_OK) ++failures;
            }
        });
    }
    for (auto &thread : threads) thread.join();
    EXPECT_EQ(0, failures.load());
}

TEST_F(zklaim_verifier, malformed_signature_has_signature_error_code) {
    memset(received->signature + 32, 0xff, 32); // Noncanonical Ed25519 scalar.
    EXPECT_EQ(ZKLAIM_INVALID_SIGNATURE, verify());
}

TEST_F(zklaim_verifier, rejects_self_issued_credentials_and_relabelled_issuer_keys) {
    verifier_test_key attacker, attacker_pub;
    ASSERT_EQ(ZKLAIM_OK, zklaim_gen_pk(&attacker.value));
    ASSERT_EQ(ZKLAIM_OK, zklaim_get_pub(attacker.value, &attacker_pub.value));
    unsigned char *key = nullptr;
    size_t key_size = 0;
    ASSERT_EQ(ZKLAIM_OK, zklaim_pub2buf(attacker_pub.value, &key, &key_size));
    std::unique_ptr<unsigned char, decltype(&free)> key_storage(key, free);
    ASSERT_EQ(sizeof(trusted_key), key_size);
    ASSERT_NE(0, memcmp(trusted_key, key, key_size));
    ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_sign(received.get(), attacker.value));
    EXPECT_EQ(0, memcmp(received->pub_key, key, key_size));

    // This is a fully valid proof and signature under the attacker's own key.
    EXPECT_EQ(ZKLAIM_OK, verify_with(received.get(), key, policy, 2));
    EXPECT_EQ(ZKLAIM_UNTRUSTED_ISSUER, verify());
    // Claiming the pinned issuer's identity cannot make its signature valid.
    memcpy(received->pub_key, trusted_key, sizeof(trusted_key));
    EXPECT_EQ(ZKLAIM_INVALID_SIGNATURE, verify());
}

TEST_F(zklaim_verifier, checks_every_reference_and_operation_in_every_payload) {
    zklaim_predicate expected[2];
    for (size_t payload = 0; payload < 2; ++payload) {
        for (size_t attr = 0; attr < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; ++attr) {
            SCOPED_TRACE(payload);
            SCOPED_TRACE(attr);
            memcpy(expected, policy, sizeof(expected));
            ++expected[payload].data_ref[attr];
            EXPECT_EQ(ZKLAIM_UNEXPECTED_PREDICATE,
                      verify_with(received.get(), trusted_key, expected, 2));
            memcpy(expected, policy, sizeof(expected));
            expected[payload].data_op[attr] =
                policy[payload].data_op[attr] == zklaim_noop ? zklaim_eq : zklaim_noop;
            EXPECT_EQ(ZKLAIM_UNEXPECTED_PREDICATE,
                      verify_with(received.get(), trusted_key, expected, 2));
        }
    }
    EXPECT_EQ(ZKLAIM_OK, verify());
}

TEST_F(zklaim_verifier, rejects_missing_extra_and_reordered_predicates) {
    EXPECT_EQ(ZKLAIM_UNEXPECTED_PREDICATE,
              verify_with(received.get(), trusted_key, policy, 1));
    const zklaim_predicate extra[] = {policy[0], policy[1], policy[0]};
    EXPECT_EQ(ZKLAIM_UNEXPECTED_PREDICATE,
              verify_with(received.get(), trusted_key, extra, 3));
    const zklaim_predicate reordered[] = {policy[1], policy[0]};
    EXPECT_EQ(ZKLAIM_UNEXPECTED_PREDICATE,
              verify_with(received.get(), trusted_key, reordered, 2));
}

TEST_F(zklaim_verifier, rejects_valid_proofs_for_weaker_prover_selected_predicates) {
    auto issued = serialize(issuer.get(), true);
    ctx_ptr prover(zklaim_context_new(), zklaim_ctx_free);
    ASSERT_NE(nullptr, prover);
    ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_deserialize(prover.get(), issued.data(), issued.size()));

    for (bool all_noop : {false, true}) {
        SCOPED_TRACE(all_noop);
        zklaim_predicate weaker[2];
        memcpy(weaker, policy, sizeof(weaker));
        weaker[0].data_ref[0] = 0; // An age >= 0 proof does not establish age >= 18.
        if (all_noop) {
            for (auto &predicate : weaker) {
                for (size_t attr = 0; attr < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; ++attr) {
                    predicate.data_ref[attr] = 0;
                    predicate.data_op[attr] = zklaim_noop;
                }
            }
        }
        auto *node = prover->pl_ctx_head;
        for (size_t i = 0; i < 2; ++i, node = node->next) {
            memcpy(node->pl.data_ref, weaker[i].data_ref, sizeof(node->pl.data_ref));
            memcpy(node->pl.data_op, weaker[i].data_op, sizeof(node->pl.data_op));
        }
        ASSERT_EQ(ZKLAIM_OK, zklaim_proof_generate(prover.get(), keys().pk, keys().pk_size,
                                                   zklaim_test_nonce));
        auto blob = serialize(prover.get());
        received.reset(zklaim_context_new());
        ASSERT_NE(nullptr, received);
        ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_deserialize(received.get(), blob.data(), blob.size()));
        zklaim_clear_pres(received.get());
        // The proof and issuer signature are valid for the weaker statement.
        ASSERT_EQ(ZKLAIM_OK, verify_with(received.get(), trusted_key, weaker, 2));
        EXPECT_EQ(ZKLAIM_UNEXPECTED_PREDICATE, verify());
    }
}

TEST_F(zklaim_verifier, still_checks_proof_after_issuer_and_policy_match) {
    received->proof_size = 1;
    EXPECT_EQ(ZKLAIM_INVALID_PROOF, verify());
    free(received->proof);
    received->proof = nullptr;
    received->proof_size = 0;
    EXPECT_EQ(ZKLAIM_INVALID_PROOF, verify());
}

TEST_F(zklaim_verifier, rejects_missing_trust_inputs_and_invalid_operations) {
    const auto &k = keys();
    EXPECT_EQ(ZKLAIM_ERROR, verify_with(nullptr, trusted_key, policy, 2));
    EXPECT_EQ(ZKLAIM_ERROR, verify_with(received.get(), nullptr, policy, 2));
    EXPECT_EQ(ZKLAIM_ERROR, verify_with(received.get(), trusted_key, nullptr, 2));
    EXPECT_EQ(ZKLAIM_ERROR, verify_with(received.get(), trusted_key, policy, 0));
    EXPECT_EQ(ZKLAIM_ERROR, verify_with(received.get(), trusted_key, policy, SIZE_MAX));
    EXPECT_EQ(ZKLAIM_ERROR, verify_with(received.get(), trusted_key, policy, 2, nullptr));
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_verify(received.get(), trusted_key, nullptr, k.vk_size,
                                              policy, 2, zklaim_test_nonce));
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_verify(received.get(), trusted_key, k.vk, 0,
                                              policy, 2, zklaim_test_nonce));
    zklaim_ctx empty = {};
    memcpy(empty.pub_key, trusted_key, sizeof(trusted_key));
    EXPECT_EQ(ZKLAIM_ERROR, verify_with(&empty, trusted_key, policy, 0));
    zklaim_predicate invalid[2];
    memcpy(invalid, policy, sizeof(invalid));
    invalid[0].data_op[0] = static_cast<zklaim_op>(0);
    received->pl_ctx_head->pl.data_op[0] = invalid[0].data_op[0];
    EXPECT_EQ(ZKLAIM_ERROR, verify_with(received.get(), trusted_key, invalid, 2));
}

TEST_F(zklaim_verifier, rejects_inconsistent_context_storage) {
    zklaim_ctx view = *received;
    view.pl_ctx_head = nullptr;
    EXPECT_EQ(ZKLAIM_ERROR, verify_with(&view, trusted_key, policy, 2));
    zklaim_wrap_payload_ctx head = *received->pl_ctx_head;
    head.next = nullptr;
    view = *received;
    view.pl_ctx_head = &head;
    EXPECT_EQ(ZKLAIM_ERROR, verify_with(&view, trusted_key, policy, 2));
    zklaim_wrap_payload_ctx extra = *received->pl_ctx_head->next;
    extra.next = &extra; // Also reject cycles without traversing forever.
    head = *received->pl_ctx_head;
    head.next = &extra;
    view.pl_ctx_head = &head;
    EXPECT_EQ(ZKLAIM_ERROR, verify_with(&view, trusted_key, policy, 2));
}

TEST_F(zklaim_verifier, rejects_presentations_replayed_for_another_nonce) {
    // A verifier that saw this presentation cannot reuse it for its own challenge.
    unsigned char other[ZKLAIM_NONCE_SIZE];
    for (size_t bit = 0; bit < 8 * ZKLAIM_NONCE_SIZE; bit += 37) {
        SCOPED_TRACE(bit);
        memcpy(other, zklaim_test_nonce, sizeof(other));
        other[bit / 8] ^= static_cast<unsigned char>(0x80 >> (bit % 8));
        EXPECT_EQ(ZKLAIM_INVALID_PROOF, verify_with(received.get(), trusted_key, policy, 2, other));
    }
    EXPECT_EQ(ZKLAIM_OK, verify());
}

TEST_F(zklaim_verifier, rejects_verification_keys_of_other_setups_and_payload_counts) {
    zklaim_test_keys other;
    ASSERT_EQ(ZKLAIM_OK, zklaim_trusted_setup(2, &other.pk, &other.pk_size, &other.vk, &other.vk_size));
    EXPECT_EQ(ZKLAIM_INVALID_PROOF, zklaim_ctx_verify(received.get(), trusted_key, other.vk, other.vk_size,
                                                      policy, 2, zklaim_test_nonce));
    const auto &one = zklaim_keys_for(1);
    ::testing::internal::CaptureStdout();
    EXPECT_EQ(ZKLAIM_INVALID_PROOF, zklaim_ctx_verify(received.get(), trusted_key, one.vk, one.vk_size,
                                                      policy, 2, zklaim_test_nonce));
    EXPECT_EQ("", ::testing::internal::GetCapturedStdout());
    EXPECT_EQ(ZKLAIM_OK, verify());
}

TEST_F(zklaim_verifier, one_setup_serves_every_credential_and_issuer_with_that_payload_count) {
    verifier_test_key second_issuer, second_pub;
    ASSERT_EQ(ZKLAIM_OK, zklaim_gen_pk(&second_issuer.value));
    ASSERT_EQ(ZKLAIM_OK, zklaim_get_pub(second_issuer.value, &second_pub.value));
    unsigned char *key = nullptr;
    size_t key_size = 0;
    ASSERT_EQ(ZKLAIM_OK, zklaim_pub2buf(second_pub.value, &key, &key_size));
    std::unique_ptr<unsigned char, decltype(&free)> key_storage(key, free);
    ASSERT_EQ(32u, key_size);

    unsigned char nonce[ZKLAIM_NONCE_SIZE];
    gcry_randomize(nonce, sizeof(nonce), GCRY_STRONG_RANDOM);
    for (uint64_t age : {UINT64_C(18), UINT64_C(77)}) {
        SCOPED_TRACE(age);
        auto blob = present(second_issuer.value, key, age, nonce);
        ASSERT_FALSE(blob.empty());
        ctx_ptr other(zklaim_context_new(), zklaim_ctx_free);
        ASSERT_NE(nullptr, other);
        ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_deserialize(other.get(), blob.data(), blob.size()));
        EXPECT_EQ(ZKLAIM_OK, verify_with(other.get(), key, policy, 2, nonce));
        EXPECT_EQ(ZKLAIM_INVALID_PROOF, verify_with(other.get(), key, policy, 2));
    }
}

} // namespace
