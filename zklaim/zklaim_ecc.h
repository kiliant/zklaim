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

#ifndef ZKLAIM_ECC_H
#define ZKLAIM_ECC_H

#include <stdio.h>
#include <gcrypt.h>
#include <stdlib.h>
#include <unistd.h>

#include <zklaim/zklaim_hash.h>


/**
 * prints a given s-expression
 *
 * @param sexp the expression to pring
 */
void print_sexp(gcry_sexp_t sexp);


/**
 * sign a given buffer
 *
 * @param buf the buffer to sign
 * @param len length of the buffer
 * @param sig where to store the signature
 * @param priv the private key used for signature
 * @return ZKLAIM_OK on success
 */
int zklaim_sign(unsigned char *buf, size_t len, gcry_sexp_t *sig, gcry_sexp_t priv);


/**
 * verify a given signature over a given buffer
 *
 * @param buf the buffer to verify
 * @param len length of the buffer
 * @param sig signature to verify
 * @param pub correspondin public key
 * @return ZKLAIM_OK on success
 */
int zklaim_verify(unsigned char *buf, size_t len, gcry_sexp_t sig, gcry_sexp_t pub);


/**
 * needed to pad msb to target length
 *
 * @param buf the buffer
 * @param size the current size
 * @param target_size the desired size to pad to
 */
void pad_msb(void *buf, size_t size, size_t target_size);


/**
 * serialize a signature to a buffer
 *
 * @param sig the signature to serialize
 * @param buf the buffer containing the serialized signature
 * @param len the length of buf in bytes
 * @return ZKLAIM_OK on success
 */
int zklaim_sig2buf(gcry_sexp_t sig, unsigned char **buf, size_t *len);


/**
 * deserialize a signature from a buffer
 *
 * @param buf the buffer containing the signature
 * @param len the length of buffer in bytes
 * @param sig the signature
 * @return ZKLAIM_OK on success
 */
int zklaim_buf2sig(unsigned char *buf, size_t len, gcry_sexp_t *sig);


/**
 * generate a private key
 *
 * @param priv the private key
 * @return ZKLAIM_OK on success
 */
int zklaim_gen_pk(gcry_sexp_t *priv);


/**
 * get the corresponding public key from a private key
 *
 * @param priv the private key
 * @param pub the public key
 * @return ZKLAIM_OK on success
 */
int zklaim_get_pub(gcry_sexp_t priv, gcry_sexp_t *pub);


/**
 * serialize a public key to a buffer
 *
 * @param pub the public key to serialize
 * @param buf the buffer containing the serialized public key
 * @param len the length of buf in bytes
 * @return ZKLAIM_OK on success
 */
int zklaim_pub2buf(gcry_sexp_t pub, unsigned char **buf, size_t *len);


/**
 * deserialize a public key from a buffer
 *
 * @param buf the buffer containing the serialized public key
 * @param len the length of buf in bytes
 * @param pub the public key
 * @return ZKLAIM_OK on success
 */
int zklaim_buf2pub(unsigned char *buf, size_t len, gcry_sexp_t *pub);


/**
 * serialize a private key to a buffer
 *
 * @param priv the private key to serialize
 * @param buf the buffer containing the serialized private key
 * @param len length of buf in bytes
 * @return ZKLAIM_OK on success
 */
int zklaim_pk2buf(gcry_sexp_t priv, unsigned char **buf, size_t *len);


/**
 * deserialize a private key from a buffer
 *
 * @param buf the buffer containing the serialized private key
 * @param len length of buf in bytes
 * @param priv the private key
 * @return ZKLAIM_OK on success
 */
int zklaim_buf2pk(unsigned char *buf, size_t len, gcry_sexp_t *priv);

#endif // ZKLAIM_ECC_H
