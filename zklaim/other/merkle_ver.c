#include "merkle.c"
#include <string.h>

int main() {
    char text1[] = "test";
    char text2[] = "hallo";
    char text3[] = "abc";
    char text4[] = "zkSNARK";
    // pre-images are application-agnostic and thus must be hashed first by the caller
    unsigned char *pres[] = {text1, text2, text3, text4};
    unsigned char *mds[4];

    for (int i=0; i<4; i++) {
        mds[i] = (unsigned char*) malloc(32);
        SHA256(pres[i], strlen(pres[i]), mds[i]);
    }

    struct merkle_root* mr;

    buildTree(&mr, 4, mds);
    print_tree(mr);

    free_tree(mr);
    return 0;
}

