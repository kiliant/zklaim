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
#include <stdio.h>

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libff/common/utils.hpp>
#include <boost/optional.hpp>

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
    int libsnark_trusted_setup(zklaim_ctx*);
    int libsnark_prove(zklaim_ctx*);
    int libsnark_verify(zklaim_ctx*);
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
bit_vector memtobv(unsigned char* mem, size_t len) {
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

// this is needed to write an ostream to memory instead of e.g. a file
class stream_mem_buf : public basic_streambuf<char> {
    public:
        stream_mem_buf(char* p, size_t len) {
            setp(p, p + len);
            setg(p, p, p + len);
        }
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

size_t libsnark_export_vk(r1cs_gg_ppzksnark_verification_key<ppT> vk, unsigned char **buf) {
    stringstream vkstream;
    size_t len;

    vkstream << vk;
    string string_vk = vkstream.str();

    len = string_vk.length();

    *buf = (unsigned char*) malloc(len);
    string_vk.copy((char*)*buf, len, 0);
    return len;
}

int libsnark_import_vk(r1cs_gg_ppzksnark_verification_key<ppT>* vk, unsigned char *buf, size_t blen) {

    stringstream vkstream;
    vkstream.write((char*)buf, blen);
    vkstream.rdbuf()->pubseekpos(0, std::ios_base::in);

    vkstream >> *vk;

    return 0;
}

size_t libsnark_export_pk(r1cs_gg_ppzksnark_proving_key<ppT> pk, unsigned char **buf) {
    stringstream vkstream;
    size_t len;
    vkstream << pk;
    string string_pk = vkstream.str();

    len = string_pk.length();

    *buf = (unsigned char*) malloc(len);
    string_pk.copy((char*)*buf, len, 0);
    return len;
}

int libsnark_import_pk(r1cs_gg_ppzksnark_proving_key<ppT>* pk, unsigned char *buf, size_t blen) {
    stringstream vkstream;
    vkstream.write((char*)buf, blen);
    vkstream.rdbuf()->pubseekpos(0, std::ios_base::in);

    vkstream >> *pk;

    return 0;
}

size_t libsnark_export_proof(r1cs_gg_ppzksnark_proof<ppT> proof, unsigned char **buf) {
    stringstream proofstream;
    size_t len;
    proofstream << proof;
    string ps = proofstream.str();

    len = ps.length();

    *buf = (unsigned char*) malloc(len);
    ps.copy((char*)*buf, len, 0);
    return len;
}

int libsnark_import_proof(r1cs_gg_ppzksnark_proof<ppT>* proof, unsigned char *buf, size_t blen) {

    stringstream proofstream;
    proofstream.write((char*)buf, blen);
    proofstream.rdbuf()->pubseekpos(0, std::ios_base::in);

    proofstream >> *proof;

    return 0;
}

// TODO
int libsnark_trusted_setup(zklaim_ctx *ctx) {
#ifndef DEBUG
    libff::inhibit_profiling_counters = 1;
    libff::inhibit_profiling_info = 1;
    int stdout_copy;
    stdout_copy = dup(STDOUT_FILENO);
    fflush(stdout);
    close(STDOUT_FILENO);
#endif
    ppT::init_public_params();
    auto keypair = generate_keypair<ppT>(ctx);

    ctx->vk_size = libsnark_export_vk(keypair.vk, &ctx->vk);
    ctx->pk_size = libsnark_export_pk(keypair.pk, &ctx->pk);

#ifndef DEBUG
    fflush(stdout);
    dup2(stdout_copy, STDOUT_FILENO);
#endif
    return 0;
}

// TODO
int libsnark_prove(zklaim_ctx *ctx) {
#ifndef DEBUG
    libff::inhibit_profiling_counters = 1;
    libff::inhibit_profiling_info = 1;
    int stdout_copy;
    stdout_copy = dup(STDOUT_FILENO);
    fflush(stdout);
    close(STDOUT_FILENO);
#endif
    ppT::init_public_params();
    r1cs_gg_ppzksnark_proving_key<ppT> pk;

    libsnark_import_pk(&pk, ctx->pk, ctx->pk_size);

    auto libsnark_proof = generate_proof<ppT>(pk, ctx);
    if (libsnark_proof == boost::none) {
#ifndef DEBUG
        fflush(stdout);
        dup2(stdout_copy, STDOUT_FILENO);
#endif

        return 1;
    }

    ctx->proof_size = libsnark_export_proof(libsnark_proof.get(), &ctx->proof);

#ifndef DEBUG
    fflush(stdout);
    dup2(stdout_copy, STDOUT_FILENO);
#endif
    return 0;
}

// TODO
int libsnark_verify(zklaim_ctx *ctx) {
#ifndef DEBUG
    int stdout_copy;
    stdout_copy = dup(STDOUT_FILENO);
    fflush(stdout);
    close(STDOUT_FILENO);
#endif
    ppT::init_public_params();
    int res;
    r1cs_gg_ppzksnark_verification_key<ppT> vk;

    libsnark_import_vk(&vk, ctx->vk, ctx->vk_size);

    r1cs_gg_ppzksnark_proof<ppT> libsnark_proof;

    libsnark_import_proof(&libsnark_proof, ctx->proof, ctx->proof_size);

    res = !verify_proof<ppT>(vk, libsnark_proof, ctx);
#ifndef DEBUG
    fflush(stdout);
    dup2(stdout_copy, STDOUT_FILENO);
#endif

    return res;
}

//#ifdef __cplusplus
//}
//#endif

#endif // ZKLAIM_WRAPPER_CPP
