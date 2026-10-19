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

#ifndef ZKLAIM_ECC_C
#define ZKLAIM_ECC_C

#include <zklaim/zklaim_ecc.h>

void print_sexp(gcry_sexp_t sexp) {
    unsigned char* buf;
    size_t size = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_DEFAULT, NULL, 0);
    buf = (unsigned char*) calloc(1, size);
    gcry_sexp_sprint(sexp, GCRYSEXP_FMT_DEFAULT, buf, size);
    printf("%s", buf);
    free(buf);
}

int zklaim_sign(unsigned char *buf, size_t len, gcry_sexp_t *sig, gcry_sexp_t priv) {
    unsigned char *dgst;
    gcry_sexp_t data;
    gcry_mpi_t dgst_mpi;
    gcry_error_t err;

    if (zklaim_calculate_hash(buf, len, &dgst) != 0) {
        return 1;
    }

    gcry_mpi_scan(&dgst_mpi, GCRYMPI_FMT_USG, dgst, 32, NULL);

    err = gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))", dgst_mpi);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        free(dgst);
        gcry_sexp_release(data);
        return 1;
    }

    err = gcry_pk_sign(sig, data, priv);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        free(dgst);
        gcry_sexp_release(data);
        return 1;
    }

    gcry_mpi_release(dgst_mpi);
    gcry_sexp_release(data);
    free(dgst);
    return 0;
}

int zklaim_verify(unsigned char *buf, size_t len, gcry_sexp_t sig, gcry_sexp_t pub) {
    gcry_error_t err;
    unsigned char *dgst;
    gcry_mpi_t dgst_mpi;
    gcry_sexp_t data;

    if (zklaim_calculate_hash(buf, len, &dgst) != 0) {
        return 1;
    }

    gcry_mpi_scan(&dgst_mpi, GCRYMPI_FMT_USG, dgst, 32, NULL);

    err = gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))", dgst_mpi);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        free(dgst);
        gcry_sexp_release(data);
        return 1;
    }


    err = gcry_pk_verify(sig, data, pub);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        free(dgst);
        gcry_sexp_release(data);
        gcry_mpi_release(dgst_mpi);
        return 1;
    }

    gcry_mpi_release(dgst_mpi);
    gcry_sexp_release(data);
    free(dgst);
    return 0;
}

// needed to pad msb to target length
void pad_msb(void *buf, size_t size, size_t target_size)
{
    char *p = (char*) buf;

    if (size < target_size){
        // shift
        memmove(&p[target_size - size], buf, size);
        // set msbs to 0
        memset(buf, 0, target_size - size);
    }
}

int zklaim_sig2buf(gcry_sexp_t sig, unsigned char **buf, size_t *len) {
    size_t rsize, ssize;

    gcry_sexp_t r, s;
    gcry_mpi_t r_mpi, s_mpi;
    gcry_error_t err;

    gcry_sexp_t pub = gcry_sexp_find_token(sig, "ecdsa", 0);

    r = gcry_sexp_find_token(pub, "r", 0);
    r_mpi = gcry_sexp_nth_mpi(r, 1, GCRYMPI_FMT_USG);
    s = gcry_sexp_find_token(pub, "s", 0);
    s_mpi = gcry_sexp_nth_mpi(s, 1, GCRYMPI_FMT_USG);

    if (buf == NULL) {
        gcry_sexp_release(r);
        gcry_sexp_release(s);
        gcry_sexp_release(pub);
        gcry_mpi_release(r_mpi);
        gcry_mpi_release(s_mpi);

        return 1;
    }

    *buf = (unsigned char*) calloc(1, 64);

    if (len)
        *len = 64;

    err = gcry_mpi_print(GCRYMPI_FMT_USG, *buf, 32, &rsize, r_mpi);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        gcry_sexp_release(r);
        gcry_sexp_release(s);
        gcry_sexp_release(pub);
        gcry_mpi_release(r_mpi);
        gcry_mpi_release(s_mpi);

        return 1;
    }

    err = gcry_mpi_print(GCRYMPI_FMT_USG, *buf+32, 32, &ssize, s_mpi);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        gcry_sexp_release(r);
        gcry_sexp_release(s);
        gcry_sexp_release(pub);
        gcry_mpi_release(r_mpi);
        gcry_mpi_release(s_mpi);

        return 1;
    }


    //if (rsize <32 || ssize < 32)
    //    printf("!!!!!\n");

    pad_msb(*buf, rsize, 32);
    pad_msb(*buf+32, ssize, 32);

    //printf("serialized %zu and %zu\n", nbytesr, nbytess);

    gcry_sexp_release(r);
    gcry_sexp_release(s);
    gcry_sexp_release(pub);
    gcry_mpi_release(r_mpi);
    gcry_mpi_release(s_mpi);
    return 0;
}

int zklaim_buf2sig(unsigned char *buf, size_t len, gcry_sexp_t *sig) {
    gcry_mpi_t r, s;
    gcry_error_t err;
    size_t readb;

    err = gcry_mpi_scan(&r, GCRYMPI_FMT_USG, buf, 32, &readb);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        return 1;
    }

    err = gcry_mpi_scan(&s, GCRYMPI_FMT_USG, buf+32, 32, &readb);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        return 1;
    }

    err = gcry_sexp_build(sig, NULL, "(sig-val (ecdsa (r %M) (s %M)))", r, s);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        return 1;
    }

    gcry_mpi_release(r);
    gcry_mpi_release(s);
    return 0;
}

int zklaim_gen_pk(gcry_sexp_t *priv) {
    gcry_error_t err;
    gcry_sexp_t parms;

    err = gcry_sexp_build(&parms, NULL, "(genkey(ecc(curve Ed25519)))");
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        return 1;
    }

    err = gcry_pk_genkey(priv, parms);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        return 1;
    }

    err = gcry_pk_testkey(*priv);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        return 1;
    }

    gcry_sexp_release(parms);
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

    err = gcry_sexp_build(pub, NULL, "(key-data (public-key (ecc (curve Ed25519) (q %b))))", 33, point);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        return 1;
    }
    return 0;
}

int zklaim_pk2buf(gcry_sexp_t priv, unsigned char **buf, size_t *len) {
    size_t sized, point_len;
    unsigned char *point;
    gcry_sexp_t d;
    gcry_mpi_t d_mpi;
    gcry_error_t err;

    if (buf == NULL || zklaim_pub2buf(priv, &point, &point_len)) {
        return 1;
    }
    d = gcry_sexp_find_token(priv, "d", 0);
    if (d == NULL) {
        free(point);
        return 1;
    }
    d_mpi = gcry_sexp_nth_mpi(d, 1, GCRYMPI_FMT_USG);
    if (d_mpi == NULL) {
        free(point);
        gcry_sexp_release(d);
        return 1;
    }

    *buf = (unsigned char*) malloc(64);
    if (*buf == NULL) {
        free(point);
        gcry_sexp_release(d);
        gcry_mpi_release(d_mpi);
        return 1;
    }
    memcpy(*buf, point, point_len);
    free(point);
    err = gcry_mpi_print(GCRYMPI_FMT_USG, *buf + 32, 32, &sized, d_mpi);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        free(*buf);
        *buf = NULL;
        gcry_sexp_release(d);
        gcry_mpi_release(d_mpi);
        return 1;
    }

    pad_msb(*buf+32, sized, 32);

    if (len)
        *len = 64;

    gcry_sexp_release(d);
    gcry_mpi_release(d_mpi);

    return 0;
}

int zklaim_buf2pk(unsigned char *buf, size_t len, gcry_sexp_t *priv) {
    gcry_mpi_t d;
    gcry_error_t err;
    if (buf == NULL || len != 64 || priv == NULL) {
        return 1;
    }
    unsigned char point[33];
    point[0] = 0x40;
    memcpy(point + 1, buf, 32);

    err = gcry_mpi_scan(&d, GCRYMPI_FMT_USG, buf + 32, 32, NULL);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        return 1;
    }

    err = gcry_sexp_build(priv, NULL, "(key-data (public-key (ecc (curve Ed25519) (q %b))) (private-key (ecc (curve Ed25519) (q %b) (d %M))))", 33, point, 33, point, d);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        gcry_mpi_release(d);

        return 1;
    }

    gcry_mpi_release(d);
    return 0;
}

#endif // ZKLAIM_ECC_C
