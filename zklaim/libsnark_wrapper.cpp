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

#ifndef ZKLAIM_WRAPPER_CPP
#define ZKLAIM_WRAPPER_CPP

#define ppT default_r1cs_ppzksnark_pp
//#define DEBUG 1

#include <stdlib.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <limits>
#include <locale>
#include <memory>
#include <stdio.h>

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libff/common/utils.hpp>

#include "snark.cpp"

extern "C" {
#include <zklaim/zklaim.h>
}

// this is probably not needed, as cmake takes care of correct compilation
// and linkage:
//#ifdef __cplusplus
//extern "C" {
//#endif

extern "C" {
    int libsnark_trusted_setup(size_t, unsigned char**, size_t*, unsigned char**, size_t*);
    int libsnark_prove(zklaim_ctx*, const unsigned char*, size_t, const unsigned char*);
    int libsnark_verify(zklaim_ctx*, const unsigned char*, size_t, const unsigned char*);
    int libsnark_import_proof(zklaim_proof**, unsigned char*, size_t);
    void libsnark_free(zklaim_proving_key*, zklaim_verification_key*, zklaim_proof*);
    size_t libsnark_export_proof(zklaim_proof*, unsigned char**);
}

typedef std::vector<bool> bit_vector;

using namespace std;
using namespace libsnark;

/**
 * this is needed to convert a memory region of length *len* to a
 * std::vector<bool> bit_vector
 */
bit_vector memtobv(const unsigned char* mem, size_t len) {
    bit_vector res(len);
    size_t wordsize = 8;
    for (size_t i = 0; i < len/wordsize; i++) {
        for (size_t k=0; k<wordsize; k++) {
            res[i*wordsize+k] = (*(mem+i) & (1ul << (8-1-k)));
        }
    }
    return res;
}

bit_vector memtobv2(unsigned char* mem, size_t len) {
    bit_vector res(len);
    size_t wordsize = 8;
    for (size_t i = 0; i < len/wordsize; i++) {
        for (size_t k=0; k<wordsize; k++) {
            res[i*wordsize+k] = (*(mem+i) & (1ul << (k)));
        }
    }
    return res;
}

// libff's decimal bigint reader assumes a digit-only token that fits its fixed
// limb array. Check formatted reads before that reader sees them; binary reads
// and separators use xsgetn and retain libff's existing wire format.
class stream_mem_buf : public basic_streambuf<char> {
    const char *cursor;
    const char *end;
    size_t digits = 0;
    static constexpr size_t limb_count =
        libff::Fr<ppT>::num_limbs < libff::Fq<ppT>::num_limbs ?
        libff::Fr<ppT>::num_limbs : libff::Fq<ppT>::num_limbs;
    // log10(2) > 301/1000, so this many digits always fit in the limb array.
    static constexpr size_t max_digits = limb_count * GMP_NUMB_BITS * 301 / 1000;

    int_type underflow() override {
        if (cursor == end) return traits_type::eof();
        const unsigned char c = *cursor;
        if (c >= '0' && c <= '9') {
            if (digits >= max_digits) throw std::ios_base::failure("oversized integer");
        } else if (c != ' ' && c != '\n' && c != '\r' && c != '\t' && c != '\v' && c != '\f') {
            throw std::ios_base::failure("invalid integer");
        }
        return traits_type::to_int_type(c);
    }

    int_type uflow() override {
        const int_type c = underflow();
        if (!traits_type::eq_int_type(c, traits_type::eof())) {
            if (c >= '0' && c <= '9') ++digits;
            else digits = 0;
            ++cursor;
        }
        return c;
    }

    std::streamsize xsgetn(char *out, std::streamsize count) override {
        const auto available = static_cast<std::streamsize>(end - cursor);
        const auto taken = std::min(count, available);
        if (taken > 0) memcpy(out, cursor, static_cast<size_t>(taken));
        cursor += taken;
        digits = 0;
        return taken;
    }

public:
    stream_mem_buf(const char *data, size_t len) : cursor(data), end(data + len) {}
    bool exhausted() const { return cursor == end; }
};

// Native integers in libsnark's serialization are collection sizes or indices.
// None can legitimately exceed the number of bytes in the whole object.
class bounded_num_get : public std::num_get<char> {
    const size_t limit;
    template<typename T>
    iter_type read(iter_type in, iter_type end, std::ios_base &stream,
                   std::ios_base::iostate &error, T &value) const {
        auto result = std::num_get<char>::do_get(in, end, stream, error, value);
        if (!(error & std::ios::failbit) && value > limit) error |= std::ios::failbit;
        return result;
    }

    iter_type do_get(iter_type in, iter_type end, std::ios_base &stream,
                     std::ios_base::iostate &error, unsigned long &value) const override {
        return read(in, end, stream, error, value);
    }
    iter_type do_get(iter_type in, iter_type end, std::ios_base &stream,
                     std::ios_base::iostate &error, unsigned long long &value) const override {
        return read(in, end, stream, error, value);
    }

public:
    explicit bounded_num_get(size_t bytes) : limit(bytes) {}
};

struct zklaim_proving_key {
    r1cs_gg_ppzksnark_proving_key<ppT> pk;
};

struct zklaim_verification_key {
    r1cs_gg_ppzksnark_verification_key<ppT> vk;
};

struct zklaim_proof {
    r1cs_gg_ppzksnark_proof<ppT> proof;
};

void libsnark_free(zklaim_proving_key* pk, zklaim_verification_key* vk, zklaim_proof* proof) {
    if (pk) {
        free(pk);
    }

    if (vk) {
        free(vk);
    }

    if (proof) {
        free(proof);
    }
}

template<typename T>
size_t libsnark_export(const T &value, unsigned char **buf) {
    if (buf == nullptr) return 0;
    *buf = nullptr;
    try {
        stringstream stream;
        stream.imbue(std::locale::classic());
        stream.exceptions(std::ios::failbit | std::ios::badbit);
        stream << value;
        const string serialized = stream.str();
        std::unique_ptr<unsigned char, decltype(&free)> storage(
            static_cast<unsigned char *>(malloc(serialized.size())), free);
        if (!storage) return 0;
        serialized.copy(reinterpret_cast<char *>(storage.get()), serialized.size());
        *buf = storage.release();
        return serialized.size();
    } catch (...) {
        return 0;
    }
}

size_t libsnark_export_vk(r1cs_gg_ppzksnark_verification_key<ppT> vk, unsigned char **buf) {
    return libsnark_export(vk, buf);
}

template<typename T>
int libsnark_import(T *value, const unsigned char *buf, size_t blen) {
    if (value == nullptr || buf == nullptr || blen == 0 ||
        blen > static_cast<size_t>(std::numeric_limits<std::streamsize>::max())) {
        return ZKLAIM_ERROR;
    }
    try {
        stream_mem_buf buffer(reinterpret_cast<const char *>(buf), blen);
        std::istream stream(&buffer);
        stream.imbue(std::locale(std::locale::classic(), new bounded_num_get(blen)));
        // Throw at the first failed read, before libsnark uses an unread count
        // or continues parsing a partially initialized object.
        stream.exceptions(std::ios::failbit | std::ios::badbit);
        T parsed;
        stream >> parsed;
        if (!stream || !buffer.exhausted()) {
            return ZKLAIM_ERROR;
        }
        std::ostringstream canonical;
        canonical.imbue(std::locale::classic());
        canonical << parsed;
        const auto encoded = canonical.str();
        if (encoded.size() != blen || memcmp(encoded.data(), buf, blen) != 0) return ZKLAIM_ERROR;
        *value = std::move(parsed);
        return ZKLAIM_OK;
    } catch (...) {
        return ZKLAIM_ERROR;
    }
}

int libsnark_import_vk(r1cs_gg_ppzksnark_verification_key<ppT>* vk, const unsigned char *buf, size_t blen) {
    if (libsnark_import(vk, buf, blen) != ZKLAIM_OK) return ZKLAIM_ERROR;
    // libsnark's sparse-vector reader accepts inconsistent counts and indices.
    const auto &rest = vk->gamma_ABC_g1.rest;
    if (!valid_sparse_vector(rest)) return ZKLAIM_ERROR;
    if (!vk->gamma_g2.is_well_formed() || !vk->delta_g2.is_well_formed() ||
        !vk->gamma_ABC_g1.first.is_well_formed()) return ZKLAIM_ERROR;
    for (const auto &point : rest.values) if (!point.is_well_formed()) return ZKLAIM_ERROR;
    return ZKLAIM_OK;
}

size_t libsnark_export_pk(r1cs_gg_ppzksnark_proving_key<ppT> pk, unsigned char **buf) {
    return libsnark_export(pk, buf);
}

int libsnark_import_pk(r1cs_gg_ppzksnark_proving_key<ppT>* pk, const unsigned char *buf, size_t blen) {
    return libsnark_import(pk, buf, blen);
}

size_t libsnark_export_proof(r1cs_gg_ppzksnark_proof<ppT> proof, unsigned char **buf) {
    return libsnark_export(proof, buf);
}

int libsnark_import_proof(r1cs_gg_ppzksnark_proof<ppT>* proof, const unsigned char *buf, size_t blen) {
    if (libsnark_import(proof, buf, blen) != ZKLAIM_OK || !proof->is_well_formed()) return ZKLAIM_ERROR;
    return ZKLAIM_OK;
}

// The circuit is sized by num_of_payloads, while witnesses and public inputs
// are read from the list; both must agree.
static bool payload_list_matches(const zklaim_ctx *ctx) {
    if (ctx->num_of_payloads == 0 || ctx->num_of_payloads > UINT32_MAX) return false;
    const zklaim_wrap_payload_ctx *node = ctx->pl_ctx_head;
    for (size_t i = 0; i < ctx->num_of_payloads; ++i) {
        if (node == nullptr) return false;
        node = node->next;
    }
    return node == nullptr;
}

int libsnark_trusted_setup(size_t num_of_payloads, unsigned char **pk_out, size_t *pk_size_out,
                           unsigned char **vk_out, size_t *vk_size_out) try {
    if (pk_out == nullptr || pk_size_out == nullptr || vk_out == nullptr || vk_size_out == nullptr) {
        return ZKLAIM_ERROR;
    }
    *pk_out = *vk_out = nullptr;
    *pk_size_out = *vk_size_out = 0;
    if (num_of_payloads == 0 || num_of_payloads > UINT32_MAX) {
        return ZKLAIM_ERROR;
    }
#ifndef DEBUG
    libff::inhibit_profiling_counters = 1;
    libff::inhibit_profiling_info = 1;
#endif
    ppT::init_public_params();
    auto keypair = generate_keypair<ppT>(num_of_payloads);

    unsigned char *vk = nullptr;
    const size_t vk_size = libsnark_export_vk(keypair.vk, &vk);
    std::unique_ptr<unsigned char, decltype(&free)> vk_storage(vk, free);
    if (vk_size == 0) return ZKLAIM_ERROR;
    unsigned char *pk = nullptr;
    const size_t pk_size = libsnark_export_pk(keypair.pk, &pk);
    std::unique_ptr<unsigned char, decltype(&free)> pk_storage(pk, free);
    if (pk_size == 0) return ZKLAIM_ERROR;
    *vk_out = vk_storage.release();
    *vk_size_out = vk_size;
    *pk_out = pk_storage.release();
    *pk_size_out = pk_size;

    return 0;
} catch (...) {
    return ZKLAIM_ERROR;
}

int libsnark_prove(zklaim_ctx *ctx, const unsigned char *pk_buf, size_t pk_size,
                   const unsigned char *nonce) try {
    if (ctx == nullptr || pk_buf == nullptr || nonce == nullptr || !payload_list_matches(ctx)) {
        return ZKLAIM_ERROR;
    }
#ifndef DEBUG
    libff::inhibit_profiling_counters = 1;
    libff::inhibit_profiling_info = 1;
#endif
    ppT::init_public_params();
    r1cs_gg_ppzksnark_proving_key<ppT> pk;

    if (libsnark_import_pk(&pk, pk_buf, pk_size) != ZKLAIM_OK) {
        return ZKLAIM_ERROR;
    }

    r1cs_gg_ppzksnark_proof<ppT> libsnark_proof;
    if (!generate_proof<ppT>(pk, ctx, nonce, libsnark_proof)) {
        return 1;
    }

    unsigned char *proof = nullptr;
    const size_t proof_size = libsnark_export_proof(libsnark_proof, &proof);
    if (proof_size == 0) return ZKLAIM_ERROR;
    free(ctx->proof);
    ctx->proof = proof;
    ctx->proof_size = proof_size;

    return 0;
} catch (...) {
    return ZKLAIM_ERROR;
}

int libsnark_verify(zklaim_ctx *ctx, const unsigned char *vk_buf, size_t vk_size,
                    const unsigned char *nonce) try {
    if (ctx == nullptr || vk_buf == nullptr || nonce == nullptr || !payload_list_matches(ctx)) {
        return ZKLAIM_ERROR;
    }
#ifndef DEBUG
    libff::inhibit_profiling_counters = 1;
    libff::inhibit_profiling_info = 1;
#endif
    ppT::init_public_params();
    int res;
    r1cs_gg_ppzksnark_verification_key<ppT> vk;

    r1cs_gg_ppzksnark_proof<ppT> libsnark_proof;
    if (libsnark_import_vk(&vk, vk_buf, vk_size) != ZKLAIM_OK ||
        libsnark_import_proof(&libsnark_proof, ctx->proof, ctx->proof_size) != ZKLAIM_OK) {
        res = ZKLAIM_ERROR;
    } else {
        res = !verify_proof<ppT>(vk, libsnark_proof, ctx, nonce);
    }
    return res;
} catch (...) {
    return ZKLAIM_ERROR;
}

//#ifdef __cplusplus
//}
//#endif

#endif // ZKLAIM_WRAPPER_CPP
