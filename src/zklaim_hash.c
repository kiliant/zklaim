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


#ifndef ZKLAIM_HASH_C
#define ZKLAIM_HASH_C

#include <zklaim/zklaim_hash.h>
#include <zklaim/zklaim.h>

void zklaim_print_hex(unsigned char *buf, size_t len) {
    for (size_t i = 0; i<len; i++) {
        printf("%.2x", *(buf+i));
    }
}

int zklaim_calculate_hash(unsigned char *buf, size_t len, unsigned char **dgst) {
    gcry_md_hd_t hash;
    unsigned char *dgst_tmp;
    gcry_error_t err = gcry_md_open(&hash, GCRY_MD_SHA256, 0);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "[%s (%d): %s] error occurred: %s\n", __FILE__, __LINE__, gcry_strsource(err), gcry_strerror(err));
        return 1;
    }

    gcry_md_write(hash, buf, len);
    gcry_md_final(hash);
    dgst_tmp = gcry_md_read(hash, 0);

    if (dgst_tmp == NULL) {
        gcry_md_close(hash);
        return ZKLAIM_ERROR;
    }

    *dgst = (unsigned char*) malloc(32);
    memcpy(*dgst, dgst_tmp, 32);

    gcry_md_close(hash);

    return ZKLAIM_OK;
}


#endif // ZKLAIM_HASH_C
