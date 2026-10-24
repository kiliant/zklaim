/*
 * This file is part of zklaim.
 * zklaim is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * zklaim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with zklaim. If not, see https://www.gnu.org/licenses/.
 */

#ifndef ZKLAIM_WIRE_H
#define ZKLAIM_WIRE_H

#include <stdint.h>
#include <zklaim/zklaim_export.h>

#define ZKLAIM_WIRE_VERSION 2
#define ZKLAIM_WIRE_HEADER_SIZE 88
#define ZKLAIM_WIRE_PRESENTATION 2
#define ZKLAIM_WIRE_CREDENTIAL 1
#define ZKLAIM_WIRE_PUBLIC_PAYLOAD_SIZE 77
#define ZKLAIM_WIRE_CREDENTIAL_PAYLOAD_SIZE 133 /* public part, flag, 55-byte witness */
#define ZKLAIM_SIGNED_PREFIX_SIZE 12

static inline void zklaim_store_u64(unsigned char *out, uint64_t value) {
    for (unsigned int i = 0; i < 8; ++i) out[i] = (unsigned char) (value >> (56 - 8 * i));
}

static inline uint64_t zklaim_load_u64(const unsigned char *in) {
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i) value = (value << 8) | in[i];
    return value;
}

static inline void zklaim_store_u32(unsigned char *out, uint32_t value) {
    for (unsigned int i = 0; i < 4; ++i) out[i] = (unsigned char) (value >> (24 - 8 * i));
}

static inline uint32_t zklaim_load_u32(const unsigned char *in) {
    return ((uint32_t) in[0] << 24) | ((uint32_t) in[1] << 16) |
           ((uint32_t) in[2] << 8) | (uint32_t) in[3];
}

#ifdef __cplusplus
extern "C" {
#endif
/** Curve identifier of the linked library, independent of caller flags. */
ZKLAIM_API unsigned char zklaim_wire_curve(void);
#ifdef __cplusplus
}
#endif

#endif
