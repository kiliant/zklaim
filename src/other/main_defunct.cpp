/**
 * THIS CODE IS DEFUNCT
 */

#include <stdlib.h>
#include <iostream>
#include <ctime>
#include <openssl/sha.h>
#include <fstream>

#include "snark.hpp"

using namespace libsnark;
using namespace std;

/**
 * converts a bare memory region to a bitvector required by libsnark
 * mem is a pointer to that memory region
 * len is the length of that memory region in BITS
 */
bit_vector memtobv(unsigned char* mem, size_t len) {
    bit_vector res(len);
    for (size_t i = 0; i < len/8; i++) {
        for (size_t k=0; k<8; k++) {
            res[i*8+k] = (*(mem+i) & (1ul << (8-1-k)));
        }
    }
    return res;
}

int main()
{
    default_r1cs_ppzksnark_pp::init_public_params();
    protoboard<Fr<default_ec_pp>> pb;

    shared_ptr<digest_variable<Fr<default_ec_pp>>> hash;
    shared_ptr<block_variable<Fr<default_ec_pp>>> input_block;
    shared_ptr<sha256_two_to_one_hash_gadget<Fr<default_ec_pp>>> hash_gadget;
    size_t input_block_length = 256;

    hash.reset(new digest_variable<Fr<default_ec_pp>>(pb, 256, "hash"));
    input_block.reset(new block_variable<Fr<default_ec_pp>>(pb, input_block_length, "input block"));

    hash_gadget.reset(new sha256_two_to_one_hash_gadget<Fr<default_ec_pp>>(pb,
                input_block_length,
                *input_block,
                *hash,
                "hash gadget"));

    hash->generate_r1cs_constraints();
    hash_gadget->generate_r1cs_constraints();

    std::vector<bool> h1_bv(256);
    std::vector<bool> r1_bv(512);

    unsigned char msg[512] = {0};
    unsigned char md[256] = {0};
    strncpy((char*) msg, "Hallo", 5);
    SHA256(msg, 64, md);

    //md[5] = ~md[5];

    h1_bv = memtobv(md, 256);
    r1_bv = memtobv(msg, 512);

    hash->generate_r1cs_witness(h1_bv);
    input_block->generate_r1cs_witness(r1_bv);
    hash_gadget->generate_r1cs_witness();


    printf("Number of constraints: %lu\n", pb.num_constraints());

    printf("==============================\n");
    printf("====== satisfied: %s ======\n", pb.is_satisfied() ? "yes" : "no");
    printf("==============================\n");
}

