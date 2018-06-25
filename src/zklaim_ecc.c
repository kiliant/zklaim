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

#include "zklaim_ecc.h"

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
    gcry_mpi_t pub_key;
    gcry_sexp_t q;
    gcry_error_t err;
    // TODO: this is ugly, but works for now
    q = gcry_sexp_find_token(priv, "q", 0);
    pub_key = gcry_sexp_nth_mpi(q, 1, GCRYMPI_FMT_USG);


    err = gcry_sexp_build(pub, NULL, "(key-data (public-key (ecc (curve Ed25519) (q %M))))", pub_key);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        gcry_mpi_release(pub_key);
        return 1;
    }

    gcry_sexp_release(q);
    gcry_mpi_release(pub_key);
    return 0;
}

int zklaim_pub2buf(gcry_sexp_t pub, unsigned char **buf, size_t *len) {
    size_t nbytes;
    gcry_error_t err;
    gcry_mpi_t pub_mpi;
    gcry_sexp_t pub_q;

    *buf = (unsigned char*) malloc(32);

    *len = 32;

    pub_q = gcry_sexp_find_token(pub, "q", 0);

    pub_mpi = gcry_sexp_nth_mpi(pub_q, 1, GCRYMPI_FMT_USG);

    err = gcry_mpi_print(GCRYMPI_FMT_USG, *buf, 32, &nbytes, pub_mpi);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        gcry_sexp_release(pub_q);
        gcry_mpi_release(pub_mpi);

        return 1;
    }

    pad_msb(*buf, nbytes, 32);

    gcry_sexp_release(pub_q);
    gcry_mpi_release(pub_mpi);

    return 0;
}

int zklaim_buf2pub(unsigned char *buf, size_t len, gcry_sexp_t *pub) {
    gcry_error_t err;
    gcry_mpi_t pub_key;

    err = gcry_mpi_scan(&pub_key, GCRYMPI_FMT_USG, buf, len, NULL);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        gcry_mpi_release(pub_key);
        return 1;
    }

    err = gcry_sexp_build(pub, NULL, "(key-data (public-key (ecc (curve Ed25519) (q %M))))", pub_key);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        gcry_mpi_release(pub_key);
        return 1;
    }

    gcry_mpi_release(pub_key);
    return 0;
}

int zklaim_pk2buf(gcry_sexp_t priv, unsigned char **buf, size_t *len) {
    size_t sized, sizeq;

    gcry_sexp_t d, q;
    gcry_mpi_t q_mpi, d_mpi;
    gcry_error_t err;

    q = gcry_sexp_find_token(priv, "q", 0);
    d = gcry_sexp_find_token(priv, "d", 0);

    q_mpi = gcry_sexp_nth_mpi(q, 1, GCRYMPI_FMT_USG);
    d_mpi = gcry_sexp_nth_mpi(d, 1, GCRYMPI_FMT_USG);

    *buf = (unsigned char*) malloc(64);

    err = gcry_mpi_print(GCRYMPI_FMT_USG, *buf, 32, &sizeq, q_mpi);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        gcry_sexp_release(q);
        gcry_sexp_release(d);
        gcry_mpi_release(q_mpi);
        gcry_mpi_release(d_mpi);

        return 1;
    }

    err = gcry_mpi_print(GCRYMPI_FMT_USG, *buf + 32, 32, &sized, d_mpi);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        gcry_sexp_release(q);
        gcry_sexp_release(d);
        gcry_mpi_release(q_mpi);
        gcry_mpi_release(d_mpi);

        return 1;
    }

    pad_msb(*buf, sizeq, 32);
    pad_msb(*buf+32, sized, 32);

    if (len)
        *len = 64;

    gcry_sexp_release(q);
    gcry_sexp_release(d);
    gcry_mpi_release(q_mpi);
    gcry_mpi_release(d_mpi);

    return 0;
}

int zklaim_buf2pk(unsigned char *buf, size_t len, gcry_sexp_t *priv) {
    gcry_mpi_t q, d;
    gcry_error_t err;
    size_t readb;

    err = gcry_mpi_scan(&q, GCRYMPI_FMT_USG, buf, 32, &readb);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        return 1;
    }

    err = gcry_mpi_scan(&d, GCRYMPI_FMT_USG, buf + 32, 32, &readb);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        gcry_mpi_release(q);

        return 1;
    }

    err = gcry_sexp_build(priv, NULL, "(key-data (public-key (ecc (curve Ed25519) (q %M))) (private-key (ecc ((curve Ed25519) (q %M) (d %M)))))", q, q, d);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        gcry_mpi_release(q);
        gcry_mpi_release(d);

        return 1;
    }

    gcry_mpi_release(q);
    gcry_mpi_release(d);
    return 0;

    return 0;
}

#endif // ZKLAIM_ECC_C
