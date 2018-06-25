#ifndef ZKLAIM_ECC_H
#define ZKLAIM_ECC_H

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

ECDSA_SIG *ecdsa_sign(unsigned char* data, size_t len, EC_KEY *eckey);

EC_KEY *load_ec_pub_key(const char* path);

EC_KEY *load_ec_priv_key(const char* path);

unsigned char *sig_to_DER(ECDSA_SIG* sig, int* size);

ECDSA_SIG *DER_to_sig(unsigned char *sig, long len);

int ecdsa_verify(unsigned char* data, size_t len, ECDSA_SIG *sig, EC_KEY *eckey);


#endif // ZKLAIM_ECC_H
