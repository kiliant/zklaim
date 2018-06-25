#include <gtest/gtest.h>
#include "merkle.c"

TEST(merkleTree, hello_world_size_8) {
    unsigned char text[] = "Hello World";

    // pre-images are application-agnostic and thus must be hashed first by the caller
    //unsigned char *pres[] = {text, text, text, text, text, text, text, text};

    int testSize = 8;

    unsigned char* pres2[testSize];

    for (int i=0; i<testSize; i++) {
        pres2[i] = text;
    }

    int size = sizeof(pres2)/sizeof(pres2[0]);

    unsigned char** mds = (unsigned char**) malloc(size*sizeof(unsigned char*));

    for (int i=0; i<size; i++) {
        unsigned char* dgst = (unsigned char*) malloc(32); // digest
        SHA256(pres2[i], strlen((const char*) pres2[i]), dgst);
        mds[i] = dgst;
    }

    struct merkle_root* mr;

    buildTree(&mr, size, mds);

    int f = open("tests/hashes/hello_world_size_8", O_RDONLY);
    if(f == -1) {
        FAIL();
    }

    unsigned char dgst_8[32];
    read(f, dgst_8, 32);
    close(f);
    ASSERT_EQ(0, memcmp(dgst_8, mr->root_hash, 32));

    free_tree(mr);
    for (int i=0; i<size; i++) {
        free(mds[i]);
    }
    free(mds);

}

// TODO: add more tests
