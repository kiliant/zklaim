/*
 *  This file is used to generate test signatures and example for the unit tests
 *
 */
#include "../zklaim_ecc.h"
#include <stdio.h>

int main() {
    gcry_sexp_t priv, pub, sig;
    printf("gen_pk: %d\n", zklaim_gen_pk(&priv));
    printf("get_pub: %d\n", zklaim_get_pub(priv, &pub));
    unsigned char* privbuf, *pubbuf;
    size_t privlen = 0, publen = 0;
    printf("pk2buf: %d\n", zklaim_pk2buf(priv, &privbuf, &privlen));
    printf("pub2buf: %d\n", zklaim_pub2buf(pub, &pubbuf, &publen));
    FILE *f;
    f = fopen("ed25519_priv", "w");
    fwrite(privbuf, privlen, 1, f);
    fclose(f);

    f = fopen("ed25519_pub", "w");
    fwrite(pubbuf, publen, 1, f);
    fclose(f);

    unsigned char *randbuf = malloc(1024);
    f = fopen("randfile", "r");
    fread(randbuf, 1024, 1, f);
    fclose(f);

    printf("sig: %d\n", zklaim_sign(randbuf, 1024, &sig, priv));

    unsigned char *sigbuf;
    size_t siglen;
    printf("sig2buf: %d\n", zklaim_sig2buf(sig, &sigbuf, &siglen));

    f = fopen("randfile_sig", "w");
    fwrite(sigbuf, siglen, 1, f);
    fclose(f);

    free(privbuf);
    free(pubbuf);
    free(sigbuf);
    gcry_sexp_release(priv);
    gcry_sexp_release(pub);
    gcry_sexp_release(sig);
    return 1;
}
