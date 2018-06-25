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


#ifndef ZKLAIM_HASH_H
#define ZKLAIM_HASH_H

#include <stdio.h>
#include <gcrypt.h>
#include <stdlib.h>
#include <unistd.h>


/**
 * print a buffer as hex characters
 *
 * @param buf the buffer to print
 * @param len length of the buffer in bytes
 */
void zklaim_print_hex(unsigned char *buf, size_t len);


/**
 * calculate the SHA256 hash over a given buffer
 *
 * @param buf the buffer to calculate the hash for
 * @param len the length of the buffer
 * @param dgst the digest will be stored in a buffer of appropriate size (32 byte in case of SHA256)
 */
int zklaim_calculate_hash(unsigned char *buf, size_t len, unsigned char **dgst);

#endif // ZKLAIM_HASH_H
