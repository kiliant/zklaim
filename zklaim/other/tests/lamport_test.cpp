#include <gtest/gtest.h>
#include "lamport.c"

TEST(a123, test1) {
    ASSERT_TRUE(1);
}

TEST(lamport, run1) {
    unsigned char msg[] = "Hello World";
    unsigned char md[SHA256_DIGEST_LENGTH] = {0};
    size_t am = 16384; // 256^2*2/8
    unsigned char *privkey = (unsigned char*) malloc(am),
                  *pubkey = (unsigned char*) malloc(am),
                  *sig = (unsigned char*) malloc(am/2);

    int res;

    if(create_private_key(privkey, pubkey)) {
        ASSERT_TRUE(0); // fail
    }

    SHA256(msg, strlen((char* )msg), md);
    sign(md, privkey, sig);

    res = verify(md, pubkey, sig);

    ASSERT_FALSE(res);
    free(privkey);
    free(pubkey);
    free(sig);
}

TEST(lamport, runFail1) {
    unsigned char msg[] = "Hello World";
    unsigned char msg2[] = "Hellb World";
    unsigned char md[SHA256_DIGEST_LENGTH] = {0};
    size_t am = 16384; // 256^2*2/8
    unsigned char *privkey = (unsigned char*) malloc(am),
                  *pubkey = (unsigned char*) malloc(am),
                  *sig = (unsigned char*) malloc(am/2);

    int res;

    if(create_private_key(privkey, pubkey)) {
        ASSERT_TRUE(0); // fail
    }

    SHA256(msg, strlen((char* )msg), md);
    sign(md, privkey, sig);

    // hash another msg
    SHA256(msg2, strlen((char* ) msg2), md);

    res = verify(md, pubkey, sig);

    ASSERT_TRUE(res);
    free(privkey);
    free(pubkey);
    free(sig);

}

TEST(lamport, runFail2) {
    unsigned char msg[] = "Hello World";
    unsigned char md[SHA256_DIGEST_LENGTH] = {0};
    size_t am = 16384; // 256^2*2/8
    unsigned char *privkey = (unsigned char*) malloc(am),
                  *pubkey = (unsigned char*) malloc(am),
                  *sig = (unsigned char*) malloc(am/2);

    int res;
    unsigned char c;

    if(create_private_key(privkey, pubkey)) {
        ASSERT_TRUE(0); // fail
    }

    SHA256(msg, strlen((char* )msg), md);
    sign(md, privkey, sig);

    // manipulate signature
    c = *(sig+20);
    c = ~c;
    *(sig+20) = c;

    res = verify(md, pubkey, sig);

    ASSERT_TRUE(res);
    free(privkey);
    free(pubkey);
    free(sig);

}

// TODO: add more tests

