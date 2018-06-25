#include "merkle.c"
#include <string.h>

int main() {
    char text[] = "Hello World";

    // pre-images are application-agnostic and thus must be hashed first by the caller
    unsigned char *pres[] = {text, text, text, text, text, text, text, text};

    int testSize = 8;

    unsigned char* pres2[testSize];

    for (int i=0; i<testSize; i++) {
        pres2[i] = text;
    }

    int size = sizeof(pres2)/sizeof(pres2[0]);

    unsigned char** mds = malloc(size*sizeof(unsigned char*));

    for (int i=0; i<size; i++) {
        unsigned char* dgst = malloc(32); // digest
        SHA256(pres2[i], strlen(pres2[i]), dgst);
        mds[i] = dgst;
    }

    //free(pres);

    struct merkle_root* mr;

    buildTree(&mr, size, mds);

    print_tree(mr);

    free_tree(mr);
    for (int i=0; i<size; i++) {
        free(mds[i]);
    }
    //free(mr);
    free(mds);
    return 0;
}

