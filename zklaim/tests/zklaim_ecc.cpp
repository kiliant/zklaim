#include <gtest/gtest.h>
extern "C" {
#include <zklaim/zklaim_ecc.h>
}

#define CHECK_GCRY_ERR(err) do {if(err != GPG_ERR_NO_ERROR) { fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err)); ASSERT_TRUE(0);}} while (0)

TEST(zklaim_ecc, can_create_key) {
    gcry_sexp_t priv;

    ASSERT_FALSE(zklaim_gen_pk(&priv));

    CHECK_GCRY_ERR(gcry_pk_testkey(priv));
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
        0x00, 0xd3, 0xbe, 0x46, 0x9d, 0x15, 0xca, 0x89,
        0x54, 0xc0, 0xed, 0x28, 0xf7, 0xeb, 0x18, 0x14,
        0x80, 0x75, 0x7c, 0x36, 0x7c, 0xc3, 0x43, 0x38,
        0xe9, 0x35, 0x22, 0x8b, 0x8b, 0xb9, 0xe2, 0x6a,
        0x40, 0x27, 0xcd, 0x96, 0x53, 0xf2, 0x0f, 0x3b,
        0xfb, 0x6a, 0xe7, 0x53, 0x12, 0x70, 0x7c, 0x31,
        0xc1, 0x69, 0x76, 0xd7, 0xe8, 0xe8, 0x1a, 0xa4,
        0x51, 0x3e, 0xaf, 0x5e, 0xa3, 0x97, 0x3a, 0x80
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

