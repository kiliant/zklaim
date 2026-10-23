/*
 * This file is part of zklaim.
 * zklaim is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * zklaim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with zklaim. If not, see https://www.gnu.org/licenses/.
 */

#include <zklaim/zklaim_ecc.h>
#include <limits.h>
#include <string.h>
#include <openssl/evp.h>

static int canonical_scalar(const unsigned char *s) {
    // RFC 8032 requires S < L. Older libgcrypt versions reduce S modulo L.
    static const unsigned char order[32] = {
        0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10
    };
    for (int i = 31; i >= 0; --i) {
        if (s[i] != order[i]) return s[i] < order[i];
    }
    return 0;
}

static int seed_matches_public(const unsigned char *point, const unsigned char *seed) {
    // Do not depend on gcry_pk_testkey checking q against the Ed25519 seed:
    // older libgcrypt versions accept inconsistent pairs.
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    if (key == NULL) return 0;
    unsigned char derived[32];
    size_t len = sizeof(derived);
    const int matches = EVP_PKEY_get_raw_public_key(key, derived, &len) == 1 &&
                        len == 32 && memcmp(derived, point, 32) == 0;
    EVP_PKEY_free(key);
    return matches;
}

// Ed25519 signs the message directly; SHA-512 and nonce derivation are part
// of EdDSA. Never reinterpret a legacy ECDSA scalar as an Ed25519 seed.
static int ed25519_key(gcry_sexp_t key) {
    if (key == NULL) return 0;
    const char *curve = gcry_pk_get_curve(key, 0, NULL);
    if (curve == NULL || strcmp(curve, "Ed25519") != 0) return 0;
    gcry_sexp_t flags = gcry_sexp_find_token(key, "flags", 0);
    int found = 0;
    for (int i = 1; i < gcry_sexp_length(flags); ++i) {
        size_t len = 0;
        const char *flag = gcry_sexp_nth_data(flags, i, &len);
        if (flag != NULL && len == 5 && memcmp(flag, "eddsa", 5) == 0) found = 1;
    }
    gcry_sexp_release(flags);
    return found;
}

static int signature_data(unsigned char *buf, size_t len, gcry_sexp_t *data) {
    *data = NULL;
    if ((buf == NULL && len != 0) || len > INT_MAX) return 1;
    return gcry_sexp_build(data, NULL,
        "(data (flags eddsa) (hash-algo sha512) (value %b))",
        (int) len, buf != NULL ? buf : (unsigned char *) "") != 0;
}

int zklaim_sign(unsigned char *buf, size_t len, gcry_sexp_t *sig, gcry_sexp_t priv) {
    gcry_sexp_t data = NULL;
    gcry_error_t err;
    if (sig == NULL) {
        return 1;
    }
    *sig = NULL;
    if (!ed25519_key(priv) || signature_data(buf, len, &data)) {
        return 1;
    }
    err = gcry_pk_sign(sig, data, priv);
    gcry_sexp_release(data);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        gcry_sexp_release(*sig);
        *sig = NULL;
        return 1;
    }
    return 0;
}

int zklaim_verify(unsigned char *buf, size_t len, gcry_sexp_t sig, gcry_sexp_t pub) {
    gcry_sexp_t data = NULL;
    gcry_error_t err;
    unsigned char *encoded = NULL;
    // Enforce algorithm, fixed-width components and canonical S for direct
    // S-expression callers as well as signatures imported from bytes.
    if (zklaim_sig2buf(sig, &encoded, NULL)) return 1;
    free(encoded);
    if (!ed25519_key(pub) || signature_data(buf, len, &data)) {
        return 1;
    }
    err = gcry_pk_verify(sig, data, pub);
    gcry_sexp_release(data);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        return 1;
    }
    return 0;
}

int zklaim_sig2buf(gcry_sexp_t sig, unsigned char **buf, size_t *len) {
    if (buf == NULL) return 1;
    *buf = NULL;
    if (len) *len = 0;
    gcry_sexp_t eddsa = gcry_sexp_find_token(sig, "eddsa", 0);
    gcry_sexp_t r = gcry_sexp_find_token(eddsa, "r", 0);
    gcry_sexp_t s = gcry_sexp_find_token(eddsa, "s", 0);
    size_t rsize = 0, ssize = 0;
    const char *rbytes = gcry_sexp_nth_data(r, 1, &rsize);
    const char *sbytes = gcry_sexp_nth_data(s, 1, &ssize);
    unsigned char *encoded = NULL;
    if (rbytes != NULL && sbytes != NULL && rsize == 32 && ssize == 32 &&
        canonical_scalar((const unsigned char *) sbytes)) {
        encoded = malloc(64);
        if (encoded != NULL) {
            // RFC 8032: the encoded point R followed by little-endian scalar S.
            memcpy(encoded, rbytes, 32);
            memcpy(encoded + 32, sbytes, 32);
        }
    }
    gcry_sexp_release(r);
    gcry_sexp_release(s);
    gcry_sexp_release(eddsa);
    if (encoded == NULL) return 1;
    *buf = encoded;
    if (len) *len = 64;
    return 0;
}

int zklaim_buf2sig(unsigned char *buf, size_t len, gcry_sexp_t *sig) {
    if (sig == NULL) return 1;
    *sig = NULL;
    if (buf == NULL || len != 64 || !canonical_scalar(buf + 32)) return 1;
    return gcry_sexp_build(sig, NULL, "(sig-val (eddsa (r %b) (s %b)))",
                           32, buf, 32, buf + 32) != 0;
}

int zklaim_gen_pk(gcry_sexp_t *priv) {
    if (priv == NULL) return 1;
    *priv = NULL;
    gcry_sexp_t parms = NULL;
    gcry_error_t err = gcry_sexp_build(&parms, NULL,
        "(genkey (ecc (curve Ed25519) (flags eddsa)))");
    if (err == 0) err = gcry_pk_genkey(priv, parms);
    if (err == 0) err = gcry_pk_testkey(*priv);
    gcry_sexp_release(parms);
    if (err != 0) {
        gcry_sexp_release(*priv);
        *priv = NULL;
        return 1;
    }
    return 0;
}

int zklaim_get_pub(gcry_sexp_t priv, gcry_sexp_t *pub) {
    unsigned char *point;
    size_t len;
    if (zklaim_pub2buf(priv, &point, &len)) {
        return 1;
    }
    int res = zklaim_buf2pub(point, len, pub);
    free(point);
    return res;
}

int zklaim_pub2buf(gcry_sexp_t pub, unsigned char **buf, size_t *len) {
    if (pub == NULL || buf == NULL || len == NULL) {
        return 1;
    }
    *buf = NULL;
    *len = 0;
    gcry_sexp_t q = gcry_sexp_find_token(pub, "q", 0);
    if (q == NULL) {
        return 1;
    }
    size_t point_len;
    const unsigned char *point = (const unsigned char*) gcry_sexp_nth_data(q, 1, &point_len);

    // Ed25519 points are bytes, not integers. Accept libgcrypt's optional
    // compressed-point prefix, but keep the serialized format at 32 bytes.
    if (point != NULL && point_len == 33 && point[0] == 0x40) {
        ++point;
        --point_len;
    }
    if (point == NULL || point_len != 32) {
        gcry_sexp_release(q);
        return 1;
    }
    *buf = (unsigned char*) malloc(32);
    if (*buf == NULL) {
        gcry_sexp_release(q);
        return 1;
    }
    memcpy(*buf, point, 32);
    *len = 32;
    gcry_sexp_release(q);
    return 0;
}

int zklaim_buf2pub(unsigned char *buf, size_t len, gcry_sexp_t *pub) {
    gcry_error_t err;
    if (buf == NULL || len != 32 || pub == NULL) {
        return 1;
    }
    // Explicitly mark the native compressed encoding and preserve leading zeros.
    unsigned char point[33];
    point[0] = 0x40;
    memcpy(point + 1, buf, 32);

    err = gcry_sexp_build(pub, NULL, "(key-data (public-key (ecc (curve Ed25519) (flags eddsa) (q %b))))", 33, point);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        return 1;
    }
    return 0;
}

int zklaim_pk2buf(gcry_sexp_t priv, unsigned char **buf, size_t *len) {
    if (buf == NULL) return 1;
    *buf = NULL;
    if (len) *len = 0;
    if (!ed25519_key(priv)) return 1;
    unsigned char *point = NULL;
    size_t point_len = 0;
    if (zklaim_pub2buf(priv, &point, &point_len)) return 1;
    gcry_sexp_t d = gcry_sexp_find_token(priv, "d", 0);
    size_t seed_len = 0;
    const char *seed = gcry_sexp_nth_data(d, 1, &seed_len);
    unsigned char *encoded = NULL;
    if (seed != NULL && seed_len == 32 &&
        seed_matches_public(point, (const unsigned char *) seed)) {
        encoded = malloc(64);
        if (encoded != NULL) {
            memcpy(encoded, point, 32);
            memcpy(encoded + 32, seed, 32);
        }
    }
    free(point);
    gcry_sexp_release(d);
    if (encoded == NULL) return 1;
    *buf = encoded;
    if (len) *len = 64;
    return 0;
}

int zklaim_buf2pk(unsigned char *buf, size_t len, gcry_sexp_t *priv) {
    if (priv == NULL) return 1;
    *priv = NULL;
    if (buf == NULL || len != 64 || !seed_matches_public(buf, buf + 32)) return 1;
    unsigned char point[33];
    point[0] = 0x40;
    memcpy(point + 1, buf, 32);
    gcry_error_t err = gcry_sexp_build(priv, NULL,
        "(key-data (public-key (ecc (curve Ed25519) (flags eddsa) (q %b)))"
        " (private-key (ecc (curve Ed25519) (flags eddsa) (q %b) (d %b))))",
        33, point, 33, point, 32, buf + 32);
    if (err == 0) err = gcry_pk_testkey(*priv);
    if (err != 0) {
        gcry_sexp_release(*priv);
        *priv = NULL;
        return 1;
    }
    return 0;
}
