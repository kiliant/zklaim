/**
 * taken from https://github.com/ebfull/lightning_circuit/ (under MIT license)
 * adapted
 */

#include <stdlib.h>
#include <iostream>
#include <ctime>
#include <openssl/sha.h>
#include <fstream>

#include "snark.hpp"
#include "libsnark_wrapper.cpp"
#include "zklaim_ecc.c"
extern "C" {
#include "zklaim.h"
}
//#include "zklaim_cred.hpp"

#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace libsnark;
using namespace std;

int main()
{
    //libff::inhibit_profiling_counters = 1;
    //libff::inhibit_profiling_info = 1;
    // Initialize the curve parameters.
    default_r1cs_ppzksnark_pp::init_public_params();
    // Generate the verifying/proving keys. (This is trusted setup!)

    zklaim_ctx ctx;
    ctx.pl_ctx_head = (zklaim_wrap_payload_ctx*) malloc(sizeof(zklaim_wrap_payload_ctx));

    ctx.pl_ctx_head->next = NULL;
    ctx.pl_ctx_head->pl.data1_ref = 18;
    ctx.pl_ctx_head->pl.data1_op = (enum zklaim_op) (zklaim_greater | zklaim_smaller);
    ctx.pl_ctx_head->pl.data2_ref = 0;
    ctx.pl_ctx_head->pl.data2_op = zklaim_eq;
    ctx.pl_ctx_head->pl.data3_ref = 0;
    ctx.pl_ctx_head->pl.data3_op = zklaim_eq;

    clock_t begin, end;
    double elapsed_secs;
    begin = clock();
    auto keypair = generate_keypair<default_r1cs_ppzksnark_pp>(&ctx);

    zklaim_verification_key zvk;
    zvk.vk = keypair.vk;
    unsigned char* buf;
    libsnark_export_vk(&zvk, &buf);

    FILE* fp = fopen("/tmp/key2", "w");
    fwrite(buf, zvk.size, 1, fp);
    fclose(fp);

    fstream fs;
    fs.open("/tmp/key", std::fstream::out);
    fs << keypair.vk;
    fs.close();

    end = clock();
    elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
    printf("keygen took %f\n", elapsed_secs);

    std::vector<bool> h1_bv(256);
    std::vector<bool> r1_bv(256);

    //auto cred = ZKLAIM_test_credential(1, 2, 3, 4, 5, 6, 7, NULL, 123, 8, 9);
    //cred.print();

    // allocate memory for one zklaim payload
    unsigned char* mem_reg = (unsigned char*) calloc(1, 32);
    unsigned char* cred = (unsigned char*) calloc(1, 2*8 + 32); // TODO: store sig in credential?

    // random salt
    int rand = open("/dev/urandom", O_RDONLY);
    read(rand, (ctx.pl_ctx_head->pl.pre + 24), 8);
    close(rand);

    // age
    uint64_t serial = 991213; // <- this is public

    uint64_t slot_1 = 189327498327421; // age
    uint64_t slot_2 = 0; // salary
    uint64_t slot_3 = 0; // permission level

    // copy age over to mem_reg
    memcpy(cred, &serial, 8);
    memcpy(ctx.pl_ctx_head->pl.pre, &slot_1, 8);
    memcpy(ctx.pl_ctx_head->pl.pre+8, &slot_2, 8);
    memcpy(ctx.pl_ctx_head->pl.pre+16, &slot_3, 8);

    /**
     * the credential is now effectively mem_reg
     * +-------------------------------------------------------------------+
     * |                       uint64_t serial_number                      |
     * +--------------+-----------------+---------------------------+------+
     * | slot_1 / age | slot_2 / salary | slot_3 / permission level | SALT |
     * +--------------+-----------------+---------------------------+------+
     * |                             SIGNATURE                             |
     * +-------------------------------------------------------------------+
     * after this, there is a signature over all data by the authority
     */


/**
 * the credential is now effectively mem_reg
 * +-------------------------------------------------------------------+
 * |  uint64_t serial_number        | uint64_t padding (unused)        |
 * +--------------------------------+----------------------------------+
 * |                         PL1 = 4*uint64_t                          |
 * |																   |
 * +-------------------------------------------------------------------+
 * |                             SIGNATURE                             |
 * +-------------------------------------------------------------------+
 * after this, there is a signature over all data by the authority
 */


    unsigned char md[32];
    SHA256(ctx.pl_ctx_head->pl.pre, 32, ctx.pl_ctx_head->pl.hash);

    memcpy(cred+2*8, md, 32);

    // sign the credential
    ECDSA_SIG *sig = NULL;
    EC_KEY *eckey = NULL, *ec_pub = NULL;
    eckey = load_ec_priv_key("src/ca_ecc_key.pem");

    sig = ecdsa_sign(cred, 2*8 + 32, eckey);

    int sizeder;
    unsigned char* sigp = sig_to_DER(sig, &sizeder);

    ec_pub = load_ec_pub_key("src/ca_ecc_key_pub.pem");

    //cred[2] = ~cred[2];
    int ret = ecdsa_verify(cred, 2*8 + 32, sig, ec_pub);

    EC_KEY_free(eckey);
    EC_KEY_free(ec_pub);
    ECDSA_SIG_free(sig);

    printf("ECDSA verification result: %d\n", ret);

    // this is the hash bitvector
    // THIS is what the VERIFIER also knows
    h1_bv = memtobv(md, 256);

    // this is the pre-image bitvector
    // ONLY the prover knows this -> PoK
    r1_bv = memtobv(mem_reg, 256);

    begin = clock();
    auto proof = generate_proof<default_r1cs_ppzksnark_pp>(keypair.pk, &ctx);
    end = clock();

    elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
    printf("proving took %f\n", elapsed_secs);

    begin = clock();
    int res = verify_proof(keypair.vk, *proof, &ctx);
    end = clock();
    elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
    printf("verifying took %f\n", elapsed_secs);
    // WTF? assert doesn't do anything: assert(res);
    //printf("verification result: %d\n", res);
    printf("==============================\n");
    printf("====== proof valid: %s ======\n", res ? "yes" : "no");
    printf("==============================\n");
    free(sigp);
    free(mem_reg);
    free(cred);
}

