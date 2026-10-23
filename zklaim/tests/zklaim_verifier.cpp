#include <gtest/gtest.h>
#include <cstring>
#include <memory>
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

    int verify() {
        return zklaim_ctx_verify(received.get(), trusted_key, policy, 2);
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

        issuer.reset(zklaim_context_new());
        ASSERT_NE(nullptr, issuer);
        memcpy(issuer->pub_key, trusted_key, sizeof(trusted_key));
        for (size_t i = 0; i < 2; ++i) {
            zklaim_payload pl = {};
            memcpy(pl.data_ref, policy[i].data_ref, sizeof(pl.data_ref));
            memcpy(pl.data_op, policy[i].data_op, sizeof(pl.data_op));
            ASSERT_EQ(ZKLAIM_OK, zklaim_set_attr(&pl, 23, 0));
            ASSERT_EQ(ZKLAIM_OK, zklaim_set_attr(&pl, 42, 1));
            ASSERT_EQ(ZKLAIM_OK, zklaim_set_attr(&pl, 599, 4));
            zklaim_add_pl(issuer.get(), pl);
        }
        zklaim_hash_ctx(issuer.get());
        ASSERT_EQ(ZKLAIM_OK, zklaim_trusted_setup(issuer.get()));
        ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_sign(issuer.get(), priv.value));
        ASSERT_EQ(ZKLAIM_OK, zklaim_proof_generate(issuer.get()));

        // Keep the issuer's witnesses for the weaker-predicate regression.
        auto issued = serialize(issuer.get(), true);
        ASSERT_FALSE(issued.empty());
        ctx_ptr blinded(zklaim_context_new(), zklaim_ctx_free);
        ASSERT_NE(nullptr, blinded);
        ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_deserialize(blinded.get(), issued.data(), issued.size()));
        zklaim_clear_pres(blinded.get());
        presentation = serialize(blinded.get());
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
    memcpy(received->pub_key, key, key_size);
    ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_sign(received.get(), attacker.value));

    // This is a fully valid proof and signature under the attacker's own key.
    EXPECT_EQ(ZKLAIM_OK, zklaim_ctx_verify(received.get(), key, policy, 2));
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
                      zklaim_ctx_verify(received.get(), trusted_key, expected, 2));
            memcpy(expected, policy, sizeof(expected));
            expected[payload].data_op[attr] =
                policy[payload].data_op[attr] == zklaim_noop ? zklaim_eq : zklaim_noop;
            EXPECT_EQ(ZKLAIM_UNEXPECTED_PREDICATE,
                      zklaim_ctx_verify(received.get(), trusted_key, expected, 2));
        }
    }
    EXPECT_EQ(ZKLAIM_OK, verify());
}

TEST_F(zklaim_verifier, rejects_missing_extra_and_reordered_predicates) {
    EXPECT_EQ(ZKLAIM_UNEXPECTED_PREDICATE,
              zklaim_ctx_verify(received.get(), trusted_key, policy, 1));
    const zklaim_predicate extra[] = {policy[0], policy[1], policy[0]};
    EXPECT_EQ(ZKLAIM_UNEXPECTED_PREDICATE,
              zklaim_ctx_verify(received.get(), trusted_key, extra, 3));
    const zklaim_predicate reordered[] = {policy[1], policy[0]};
    EXPECT_EQ(ZKLAIM_UNEXPECTED_PREDICATE,
              zklaim_ctx_verify(received.get(), trusted_key, reordered, 2));
}

TEST_F(zklaim_verifier, rejects_valid_proofs_for_weaker_prover_selected_predicates) {
    auto issued = serialize(issuer.get(), true);
    ctx_ptr prover(zklaim_context_new(), zklaim_ctx_free);
    ASSERT_NE(nullptr, prover);
    ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_deserialize(prover.get(), issued.data(), issued.size()));
    prover->pk = static_cast<unsigned char *>(malloc(issuer->pk_size));
    ASSERT_NE(nullptr, prover->pk);
    prover->pk_size = issuer->pk_size;
    memcpy(prover->pk, issuer->pk, issuer->pk_size);

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
        ASSERT_EQ(ZKLAIM_OK, zklaim_proof_generate(prover.get()));
        auto blob = serialize(prover.get());
        received.reset(zklaim_context_new());
        ASSERT_NE(nullptr, received);
        ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_deserialize(received.get(), blob.data(), blob.size()));
        zklaim_clear_pres(received.get());
        // The proof and issuer signature are valid for the weaker statement.
        ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_verify(received.get(), trusted_key, weaker, 2));
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
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_verify(nullptr, trusted_key, policy, 2));
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_verify(received.get(), nullptr, policy, 2));
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_verify(received.get(), trusted_key, nullptr, 2));
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_verify(received.get(), trusted_key, policy, 0));
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_verify(received.get(), trusted_key, policy, SIZE_MAX));
    zklaim_ctx empty = {};
    memcpy(empty.pub_key, trusted_key, sizeof(trusted_key));
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_verify(&empty, trusted_key, policy, 0));
    zklaim_predicate invalid[2];
    memcpy(invalid, policy, sizeof(invalid));
    invalid[0].data_op[0] = static_cast<zklaim_op>(0);
    received->pl_ctx_head->pl.data_op[0] = invalid[0].data_op[0];
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_verify(received.get(), trusted_key, invalid, 2));
}

TEST_F(zklaim_verifier, rejects_inconsistent_context_storage) {
    zklaim_ctx view = *received;
    view.pl_ctx_head = nullptr;
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_verify(&view, trusted_key, policy, 2));
    view = *received;
    view.vk = nullptr;
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_verify(&view, trusted_key, policy, 2));
    view = *received;
    view.vk_size = SIZE_MAX;
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_verify(&view, trusted_key, policy, 2));
    zklaim_wrap_payload_ctx head = *received->pl_ctx_head;
    head.next = nullptr;
    view = *received;
    view.pl_ctx_head = &head;
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_verify(&view, trusted_key, policy, 2));
    zklaim_wrap_payload_ctx extra = *received->pl_ctx_head->next;
    extra.next = &extra; // Also reject cycles without traversing forever.
    head = *received->pl_ctx_head;
    head.next = &extra;
    view.pl_ctx_head = &head;
    EXPECT_EQ(ZKLAIM_ERROR, zklaim_ctx_verify(&view, trusted_key, policy, 2));
}

} // namespace
