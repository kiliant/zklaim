#ifndef ZKLAIM_ECC_C
#define ZKLAIM_ECC_C

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "zklaim_ecc.h"

/*
 * signs given data using the EC_KEY
 */
ECDSA_SIG *ecdsa_sign(unsigned char* data, size_t len, EC_KEY *eckey) {
    ECDSA_SIG *sig = NULL;
    unsigned char md[32];
    SHA256(data, len, md);
    if (eckey == NULL) {
        printf("eckey should not be NULL\n");
        return NULL;
    }
    sig = ECDSA_do_sign(md, 32, eckey);
    return sig;
}

EC_KEY *load_ec_pub_key(const char* path) {
    EC_KEY *eckey = NULL;
    FILE* fp = fopen(path, "r");
    if (fp == NULL) {
        printf("Could not load public key!\n");
        return NULL;
    }
    eckey = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return eckey;
}

EC_KEY *load_ec_priv_key(const char* path) {
    EC_KEY *eckey = NULL;
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        printf("Could not load private key!\n");
        return NULL;
    }
    eckey = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return eckey;
}

unsigned char *sig_to_DER(ECDSA_SIG* sig, int* size) {
    long sizeder = 0;
    unsigned char* sigder = NULL;
    sizeder = i2d_ECDSA_SIG(sig, NULL);

    *size = i2d_ECDSA_SIG(sig, &sigder);

    return sigder;
}

ECDSA_SIG *DER_to_sig(unsigned char *sig, long len) {
    return d2i_ECDSA_SIG(NULL, (const unsigned char**) &sig, len);
}

int ecdsa_verify(unsigned char* data, size_t len, ECDSA_SIG *sig, EC_KEY *eckey) {
    int ret = 0;
    unsigned char md[32];

    if (eckey == NULL) {
        printf("key should not be NULL!\n");
        return -1;
    }

    if (sig == NULL) {
        printf("sig should not be NULL!\n");
        return -1;
    }

    SHA256(data, len, md);
    ret = ECDSA_do_verify(md, 32, sig, eckey);

    return ret;
}

#endif // ZKLAIM_ECC_C
