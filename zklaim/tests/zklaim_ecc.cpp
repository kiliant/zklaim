#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <openssl/evp.h>
extern "C" {
#include <zklaim/zklaim_ecc.h>
#include <zklaim/zklaim.h>
#include <zklaim/zklaim_wire.h>
}

#define CHECK_GCRY_ERR(err) do {if(err != GPG_ERR_NO_ERROR) { fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err)); ASSERT_TRUE(0);}} while (0)

TEST(zklaim_ecc, can_create_key) {
    gcry_sexp_t priv;

    ASSERT_FALSE(zklaim_gen_pk(&priv));

    CHECK_GCRY_ERR(gcry_pk_testkey(priv));
}

TEST(zklaim_ecc, signature_round_trip_verifies) {
    gcry_sexp_t priv, pub, sig, restored;
    ASSERT_EQ(0, zklaim_gen_pk(&priv));
    ASSERT_EQ(0, zklaim_get_pub(priv, &pub));
    unsigned char message[] = "signature round trip";
    ASSERT_EQ(0, zklaim_sign(message, sizeof(message), &sig, priv));
    unsigned char *buf = nullptr;
    size_t len = 0;
    ASSERT_EQ(0, zklaim_sig2buf(sig, &buf, &len));
    ASSERT_EQ(64u, len);
    ASSERT_EQ(0, zklaim_buf2sig(buf, len, &restored));
    EXPECT_EQ(0, zklaim_verify(message, sizeof(message), restored, pub));
    message[0] ^= 1;
    EXPECT_NE(0, zklaim_verify(message, sizeof(message), restored, pub));
    free(buf);
    gcry_sexp_release(restored);
    gcry_sexp_release(sig);
    gcry_sexp_release(pub);
    gcry_sexp_release(priv);
}

TEST(zklaim_ecc, rejects_malformed_signatures_without_output) {
    const char *expressions[] = {
        "(sig-val(rsa(s #01#)))",
        "(sig-val(ecdsa(r #01#)))",
        "(sig-val(ecdsa(s #01#)))",
        "(sig-val(ecdsa(r)(s #01#)))"
    };
    for (const char *expression : expressions) {
        SCOPED_TRACE(expression);
        gcry_sexp_t sig;
        CHECK_GCRY_ERR(gcry_sexp_new(&sig, expression, 0, 1));
        unsigned char *buf = nullptr;
        size_t len = 99;
        EXPECT_NE(0, zklaim_sig2buf(sig, &buf, &len));
        EXPECT_EQ(nullptr, buf);
        EXPECT_EQ(0u, len);
        gcry_sexp_release(sig);
    }
}

TEST(zklaim_ecc, rejects_oversized_signature_components_without_output) {
    unsigned char component[33] = {};
    for (bool large_r : {false, true}) {
        SCOPED_TRACE(large_r);
        gcry_sexp_t sig;
        CHECK_GCRY_ERR(gcry_sexp_build(&sig, NULL,
            "(sig-val(eddsa(r %b)(s %b)))", large_r ? 33 : 32, component,
            large_r ? 32 : 33, component));
        unsigned char *buf = nullptr;
        size_t len = 99;
        EXPECT_NE(0, zklaim_sig2buf(sig, &buf, &len));
        EXPECT_EQ(nullptr, buf);
        EXPECT_EQ(0u, len);
        gcry_sexp_release(sig);
    }
}

TEST(zklaim_ecc, rejects_invalid_signature_buffers) {
    unsigned char buf[65] = {0};
    gcry_sexp_t sig = nullptr;
    for (size_t len : {0u, 63u, 65u}) {
        EXPECT_NE(0, zklaim_buf2sig(buf, len, &sig));
        EXPECT_EQ(nullptr, sig);
    }
    EXPECT_NE(0, zklaim_buf2sig(NULL, 64, &sig));
    EXPECT_EQ(nullptr, sig);
    unsigned char *encoded = nullptr;
    size_t len = 99;
    EXPECT_NE(0, zklaim_sig2buf(NULL, &encoded, &len));
    EXPECT_EQ(nullptr, encoded);
    EXPECT_EQ(0u, len);
    EXPECT_NE(0, zklaim_sign(buf, sizeof(buf), &sig, NULL));
    EXPECT_EQ(nullptr, sig);
}

TEST(zklaim_ecc, can_get_pub) {
    unsigned char *privbuf = (unsigned char*) malloc(64);
    unsigned char *pubbuf, *pubbuf_ref = (unsigned char*) malloc(32);
    size_t publen;
    gcry_sexp_t priv, pub;
    FILE *f;
    f = fopen("tests/ed25519_priv", "r");
    if (f == NULL) {
        ASSERT_TRUE(0);
    }
    size_t rd = fread(privbuf, 1, 64, f);
    fclose(f);

    ASSERT_FALSE(zklaim_buf2pk(privbuf, rd, &priv));

    ASSERT_FALSE(zklaim_get_pub(priv, &pub));

    ASSERT_FALSE(zklaim_pub2buf(pub, &pubbuf, &publen));

    f = fopen("tests/ed25519_pub", "r");
    if (f == NULL) {
        ASSERT_TRUE(0);
    }
    fread(pubbuf_ref, 32, 1, f);
    fclose(f);


    ASSERT_FALSE(memcmp(pubbuf, pubbuf_ref, 32));
}

TEST(zklaim_ecc, can_serialize_pub) {
    unsigned char *privbuf = (unsigned char*) malloc(64);
    gcry_sexp_t priv, pub;
    FILE *f;
    f = fopen("tests/ed25519_priv", "r");
    if (f == NULL) {
        ASSERT_TRUE(0);
    }
    size_t rd = fread(privbuf, 1, 64, f);
    fclose(f);

    ASSERT_FALSE(zklaim_buf2pk(privbuf, rd, &priv));

    ASSERT_FALSE(zklaim_get_pub(priv, &pub));

    unsigned char *pubbuf, *pubbuf_ref = (unsigned char*) malloc(32);
    size_t publen;
    ASSERT_FALSE(zklaim_pub2buf(pub, &pubbuf, &publen));

    f = fopen("tests/ed25519_pub", "r");
    fread(pubbuf_ref, 32, 1, f);
    fclose(f);

    ASSERT_FALSE(memcmp(pubbuf, pubbuf_ref, 32));
    free(pubbuf);
    free(pubbuf_ref);
    free(privbuf);
}

TEST(zklaim_ecc, can_serialize_priv) {
    unsigned char *privbuf = (unsigned char*) malloc(64);
    gcry_sexp_t priv;
    FILE *f;
    f = fopen("tests/ed25519_priv", "r");
    if (f == NULL) {
        ASSERT_TRUE(0);
    }
    size_t rd = fread(privbuf, 1, 64, f);
    fclose(f);

    ASSERT_FALSE(zklaim_buf2pk(privbuf, rd, &priv));

    unsigned char *privbuf_ser;
    size_t privlen;
    ASSERT_FALSE(zklaim_pk2buf(priv, &privbuf_ser, &privlen));

    CHECK_GCRY_ERR(gcry_pk_testkey(priv));

    ASSERT_FALSE(memcmp(privbuf, privbuf_ser, 64));

    free(privbuf);
    free(privbuf_ser);
}

TEST(DISABLED_zklaim_ecc, can_deserizalize_pub) {
    // TODO
    ASSERT_FALSE(false);
}

TEST(zklaim_ecc, preserves_leading_zero_public_key) {
    // Test-only key: a valid Ed25519 point whose first byte is zero.
    unsigned char key[] = {
        0x00, 0x00, 0x1f, 0x8b, 0xea, 0x42, 0xb3, 0xc7,
        0x4c, 0x50, 0xaa, 0x35, 0x89, 0xb1, 0xaa, 0x06,
        0x5f, 0x19, 0x68, 0x57, 0xdb, 0x97, 0xa7, 0x5e,
        0x4a, 0x54, 0x95, 0x3f, 0x09, 0x3e, 0x67, 0x72,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24
    };
    gcry_sexp_t priv, pub, restored_pub, sig;
    ASSERT_EQ(0, zklaim_buf2pk(key, sizeof(key), &priv));
    CHECK_GCRY_ERR(gcry_pk_testkey(priv));
    ASSERT_EQ(0, zklaim_get_pub(priv, &pub));

    unsigned char *pubbuf, *privbuf;
    size_t publen, privlen;
    ASSERT_EQ(0, zklaim_pub2buf(pub, &pubbuf, &publen));
    ASSERT_EQ(32u, publen);
    ASSERT_EQ(0, memcmp(key, pubbuf, publen));
    ASSERT_EQ(0, zklaim_pk2buf(priv, &privbuf, &privlen));
    ASSERT_EQ(sizeof(key), privlen);
    ASSERT_EQ(0, memcmp(key, privbuf, privlen));
    ASSERT_EQ(0, zklaim_buf2pub(pubbuf, publen, &restored_pub));

    unsigned char message[] = "leading-zero public key regression";
    ASSERT_EQ(0, zklaim_sign(message, sizeof(message), &sig, priv));
    ASSERT_EQ(0, zklaim_verify(message, sizeof(message), sig, pub));
    ASSERT_EQ(0, zklaim_verify(message, sizeof(message), sig, restored_pub));

    gcry_sexp_release(sig);
    gcry_sexp_release(restored_pub);
    gcry_sexp_release(pub);
    gcry_sexp_release(priv);
    free(pubbuf);
    free(privbuf);
}

TEST(zklaim_ecc, extracts_native_public_point_without_losing_zero_bytes) {
    unsigned char point[32] = {0};
    point[1] = 0x42;
    gcry_sexp_t native_priv, pub;
    CHECK_GCRY_ERR(gcry_sexp_build(&native_priv, NULL,
        "(private-key(ecc(curve Ed25519)(q %b)(d #01#)))",
        static_cast<int>(sizeof(point)), point));
    ASSERT_EQ(0, zklaim_get_pub(native_priv, &pub));
    gcry_sexp_t q = gcry_sexp_find_token(pub, "q", 0);
    size_t qlen;
    const unsigned char *encoded = reinterpret_cast<const unsigned char *>(
        gcry_sexp_nth_data(q, 1, &qlen));
    ASSERT_NE(nullptr, encoded);
    if (qlen == 33 && encoded[0] == 0x40) {
        ++encoded;
        --qlen;
    }
    ASSERT_EQ(sizeof(point), qlen);
    ASSERT_EQ(0, memcmp(point, encoded, qlen));
    gcry_sexp_release(q);
    gcry_sexp_release(pub);
    gcry_sexp_release(native_priv);
}

TEST(zklaim_ecc, round_trips_public_point_bytes) {
    const unsigned char first_bytes[] = {0x00, 0x04, 0x40, 0x80, 0xff};
    for (unsigned char first : first_bytes) {
        SCOPED_TRACE(static_cast<unsigned int>(first));
        unsigned char point[32] = {0};
        point[0] = first;
        point[1] = 0x42;
        for (bool prefixed : {false, true}) {
            SCOPED_TRACE(prefixed);
            unsigned char encoded[33];
            encoded[0] = 0x40;
            memcpy(encoded + 1, point, sizeof(point));
            gcry_sexp_t pub, restored;
            CHECK_GCRY_ERR(gcry_sexp_build(&pub, NULL,
                "(public-key(ecc(curve Ed25519)(q %b)))",
                prefixed ? 33 : 32, prefixed ? encoded : point));
            unsigned char *buf;
            size_t len;
            ASSERT_EQ(0, zklaim_pub2buf(pub, &buf, &len));
            ASSERT_EQ(sizeof(point), len);
            ASSERT_EQ(0, memcmp(point, buf, len));
            ASSERT_EQ(0, zklaim_buf2pub(buf, len, &restored));
            gcry_sexp_t q = gcry_sexp_find_token(restored, "q", 0);
            size_t qlen;
            const char *qdata = gcry_sexp_nth_data(q, 1, &qlen);
            ASSERT_NE(nullptr, qdata);
            ASSERT_EQ(sizeof(encoded), qlen);
            ASSERT_EQ(0, memcmp(encoded, qdata, qlen));
            gcry_sexp_release(q);
            gcry_sexp_release(restored);
            gcry_sexp_release(pub);
            free(buf);
        }
    }
}

TEST(zklaim_ecc, rejects_invalid_key_lengths) {
    unsigned char buf[65] = {0};
    gcry_sexp_t key = nullptr;
    for (size_t len : {0u, 31u, 33u}) {
        ASSERT_NE(0, zklaim_buf2pub(buf, len, &key));
    }
    for (size_t len : {0u, 63u, 65u}) {
        ASSERT_NE(0, zklaim_buf2pk(buf, len, &key));
    }
    for (int len : {31, 33}) {
        CHECK_GCRY_ERR(gcry_sexp_build(&key, NULL,
            "(public-key(ecc(curve Ed25519)(q %b)))", len, buf));
        unsigned char *point = nullptr;
        size_t point_len;
        ASSERT_NE(0, zklaim_pub2buf(key, &point, &point_len));
        ASSERT_EQ(nullptr, point);
        gcry_sexp_release(key);
    }
}

TEST(zklaim_ecc, can_deserialize_priv) {
    unsigned char *privbuf = (unsigned char*) malloc(64);
    gcry_sexp_t priv;
    FILE *f;
    f = fopen("tests/ed25519_priv", "r");
    if (f == NULL) {
        ASSERT_TRUE(0);
    }
    size_t rd = fread(privbuf, 1, 64, f);
    fclose(f);

    ASSERT_FALSE(zklaim_buf2pk(privbuf, rd, &priv));

    CHECK_GCRY_ERR(gcry_pk_testkey(priv));

    gcry_sexp_release(priv);
    free(privbuf);
}


TEST(DISABLED_zklaim_ecc, can_serialize_sig) {
    // TODO
    ASSERT_FALSE(false);
}

TEST(DISABLED_zklaim_ecc, can_deserialize_sig) {
    // TODO
    ASSERT_FALSE(false);
}

TEST(DISABLED_zklaim_ecc, can_sign) {
    // TODO
    ASSERT_FALSE(false);
}

TEST(DISABLED_zklaim_ecc, can_verify) {
    // TODO
    ASSERT_FALSE(false);
}

TEST(DISABLED_zklaim_ecc, can_detect_invalid_sig) {
    // TODO
    ASSERT_FALSE(false);
}

TEST(DISABLED_zklaim_ecc, can_detect_invalid_pub) {
    // TODO
    ASSERT_FALSE(false);
}

TEST(DISABLED_zklaim_ecc, can_detect_invalid_data) {
    // TODO
    ASSERT_FALSE(false);
}

namespace {
std::vector<unsigned char> ed25519_hex(const char *hex) {
    std::vector<unsigned char> bytes;
    while (*hex) {
        auto nibble = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        bytes.push_back(static_cast<unsigned char>((nibble(hex[0]) << 4) | nibble(hex[1])));
        hex += 2;
    }
    return bytes;
}
} // namespace

TEST(zklaim_ecc, matches_rfc8032_and_interoperates_with_openssl) {
    // RFC 8032 section 7.1, tests 1 and 2 (pure Ed25519, no external prehash).
    const char *seeds[] = {
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    };
    const char *public_keys[] = {
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    };
    const char *messages[] = {"", "72"};
    const char *signatures[] = {
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    };
    for (size_t i = 0; i < 2; ++i) {
        SCOPED_TRACE(i);
        auto seed = ed25519_hex(seeds[i]);
        auto pub_bytes = ed25519_hex(public_keys[i]);
        auto message = ed25519_hex(messages[i]);
        const auto expected = ed25519_hex(signatures[i]);
        auto private_bytes = pub_bytes;
        private_bytes.insert(private_bytes.end(), seed.begin(), seed.end());
        gcry_sexp_t priv = nullptr, pub = nullptr, sig = nullptr;
        ASSERT_EQ(0, zklaim_buf2pk(private_bytes.data(), private_bytes.size(), &priv));
        ASSERT_EQ(0, zklaim_buf2pub(pub_bytes.data(), pub_bytes.size(), &pub));
        ASSERT_EQ(0, zklaim_sign(message.data(), message.size(), &sig, priv));
        unsigned char *encoded = nullptr;
        size_t encoded_size = 0;
        ASSERT_EQ(0, zklaim_sig2buf(sig, &encoded, &encoded_size));
        std::unique_ptr<unsigned char, decltype(&free)> storage(encoded, free);
        ASSERT_EQ(expected.size(), encoded_size);
        EXPECT_EQ(0, memcmp(expected.data(), encoded, encoded_size));
        EXPECT_EQ(0, zklaim_verify(message.data(), message.size(), sig, pub));

        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> openssl_key(
            EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size()), EVP_PKEY_free);
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        ASSERT_NE(nullptr, openssl_key);
        ASSERT_NE(nullptr, md);
        ASSERT_EQ(1, EVP_DigestVerifyInit(md.get(), nullptr, nullptr, nullptr, openssl_key.get()));
        EXPECT_EQ(1, EVP_DigestVerify(md.get(), encoded, encoded_size, message.data(), message.size()));
        ASSERT_EQ(1, EVP_DigestSignInit(md.get(), nullptr, nullptr, nullptr, openssl_key.get()));
        unsigned char openssl_signature[64];
        size_t openssl_size = sizeof(openssl_signature);
        ASSERT_EQ(1, EVP_DigestSign(md.get(), openssl_signature, &openssl_size, message.data(), message.size()));
        EXPECT_EQ(0, memcmp(expected.data(), openssl_signature, openssl_size));
        gcry_sexp_release(sig);
        ASSERT_EQ(0, zklaim_buf2sig(openssl_signature, openssl_size, &sig));
        EXPECT_EQ(0, zklaim_verify(message.data(), message.size(), sig, pub));
        gcry_sexp_release(sig);
        // A repeated signing operation has the same deterministic RFC signature.
        ASSERT_EQ(0, zklaim_sign(message.data(), message.size(), &sig, priv));
        unsigned char *again = nullptr;
        size_t again_size = 0;
        ASSERT_EQ(0, zklaim_sig2buf(sig, &again, &again_size));
        EXPECT_EQ(0, memcmp(expected.data(), again, again_size));
        free(again);
        gcry_sexp_release(sig);
        gcry_sexp_release(pub);
        gcry_sexp_release(priv);
    }
}

TEST(zklaim_ecc, signature_encoding_preserves_leading_zero_octets) {
    unsigned char bytes[64] = {};
    bytes[1] = 0x80;
    bytes[33] = 0x40;
    gcry_sexp_t sig = nullptr;
    ASSERT_EQ(0, zklaim_buf2sig(bytes, sizeof(bytes), &sig));
    unsigned char *encoded = nullptr;
    size_t size = 0;
    ASSERT_EQ(0, zklaim_sig2buf(sig, &encoded, &size));
    ASSERT_EQ(sizeof(bytes), size);
    EXPECT_EQ(0, memcmp(bytes, encoded, size));
    free(encoded);
    gcry_sexp_release(sig);
}

TEST(zklaim_ecc, rejects_legacy_ecdsa_keys_and_inconsistent_seed_pairs) {
    gcry_sexp_t params = nullptr, legacy = nullptr, sig = nullptr;
    CHECK_GCRY_ERR(gcry_sexp_build(&params, nullptr, "(genkey(ecc(curve Ed25519)))"));
    CHECK_GCRY_ERR(gcry_pk_genkey(&legacy, params));
    unsigned char message[] = "legacy keys must be regenerated";
    EXPECT_NE(0, zklaim_sign(message, sizeof(message), &sig, legacy));
    EXPECT_EQ(nullptr, sig);
    unsigned char *encoded = nullptr;
    size_t size = 0;
    EXPECT_NE(0, zklaim_pk2buf(legacy, &encoded, &size));
    EXPECT_EQ(nullptr, encoded);
    gcry_sexp_release(legacy);
    gcry_sexp_release(params);
    unsigned char inconsistent[64] = {};
    EXPECT_NE(0, zklaim_buf2pk(inconsistent, sizeof(inconsistent), &legacy));
    EXPECT_EQ(nullptr, legacy);
    auto mismatched = ed25519_hex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    mismatched.back() ^= 1;
    EXPECT_NE(0, zklaim_buf2pk(mismatched.data(), mismatched.size(), &legacy));
    EXPECT_EQ(nullptr, legacy);
}

TEST(zklaim_ecc, context_signature_matches_specified_domain_and_lengths) {
    auto pub = ed25519_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    auto seed = ed25519_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    auto bytes = pub;
    bytes.insert(bytes.end(), seed.begin(), seed.end());
    gcry_sexp_t key = nullptr;
    ASSERT_EQ(0, zklaim_buf2pk(bytes.data(), bytes.size(), &key));
    zklaim_ctx ctx = {};
    zklaim_wrap_payload_ctx payload = {};
    for (size_t i = 0; i < 32; ++i) payload.pl.hash[i] = static_cast<unsigned char>(i);
    ctx.pl_ctx_head = &payload;
    ctx.num_of_payloads = 1;
    ASSERT_EQ(ZKLAIM_OK, zklaim_ctx_sign(&ctx, key));
    gcry_sexp_release(key);
    EXPECT_EQ(0, memcmp(pub.data(), ctx.pub_key, sizeof(ctx.pub_key)));
    // The verification key is pinned by verifiers and not part of the signature.
    std::vector<unsigned char> signed_bytes = {
        'Z','K','S','G', 0,2, 1,zklaim_wire_curve(), 0,0,0,1
    };
    signed_bytes.insert(signed_bytes.end(), payload.pl.hash, payload.pl.hash + 32);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> openssl_key(
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub.data(), pub.size()), EVP_PKEY_free);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(nullptr, openssl_key);
    ASSERT_NE(nullptr, md);
    ASSERT_EQ(1, EVP_DigestVerifyInit(md.get(), nullptr, nullptr, nullptr, openssl_key.get()));
    EXPECT_EQ(1, EVP_DigestVerify(md.get(), ctx.signature, sizeof(ctx.signature), signed_bytes.data(), signed_bytes.size()));
    signed_bytes[5] ^= 1;
    EXPECT_NE(1, EVP_DigestVerify(md.get(), ctx.signature, sizeof(ctx.signature), signed_bytes.data(), signed_bytes.size()));
}

TEST(zklaim_ecc, rejects_ecdsa_labels_and_noncanonical_ed25519_scalars) {
    auto pub_bytes = ed25519_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    auto bytes = ed25519_hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    const auto order = ed25519_hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    gcry_sexp_t pub = nullptr, sig = nullptr;
    ASSERT_EQ(0, zklaim_buf2pub(pub_bytes.data(), pub_bytes.size(), &pub));
    CHECK_GCRY_ERR(gcry_sexp_build(&sig, nullptr, "(sig-val(ecdsa(r %b)(s %b)))", 32, bytes.data(), 32, bytes.data() + 32));
    EXPECT_NE(0, zklaim_verify(nullptr, 0, sig, pub));
    gcry_sexp_release(sig);
    // S + L represents the same group scalar but is forbidden by RFC 8032.
    unsigned int carry = 0;
    for (size_t i = 0; i < 32; ++i) {
        carry += static_cast<unsigned int>(bytes[32 + i]) + order[i];
        bytes[32 + i] = static_cast<unsigned char>(carry);
        carry >>= 8;
    }
    EXPECT_NE(0, zklaim_buf2sig(bytes.data(), bytes.size(), &sig));
    EXPECT_EQ(nullptr, sig);
    CHECK_GCRY_ERR(gcry_sexp_build(&sig, nullptr, "(sig-val(eddsa(r %b)(s %b)))", 32, bytes.data(), 32, bytes.data() + 32));
    EXPECT_NE(0, zklaim_verify(nullptr, 0, sig, pub));
    gcry_sexp_release(sig);
    gcry_sexp_release(pub);
}
