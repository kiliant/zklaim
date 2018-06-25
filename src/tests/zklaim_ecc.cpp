#include <gtest/gtest.h>
extern "C" {
#include "zklaim_ecc.h"
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
    size_t rd = fread(privbuf, 64, 1, f);
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
    size_t rd = fread(privbuf, 64, 1, f);
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
    size_t rd = fread(privbuf, 64, 1, f);
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

TEST(zklaim_ecc, can_deserialize_priv) {
    unsigned char *privbuf = (unsigned char*) malloc(64);
    gcry_sexp_t priv;
    FILE *f;
    f = fopen("tests/ed25519_priv", "r");
    if (f == NULL) {
        ASSERT_TRUE(0);
    }
    size_t rd = fread(privbuf, 64, 1, f);
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

