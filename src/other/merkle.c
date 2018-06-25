#ifndef MERKLE_C
#define MERKLE_C

/* using SHA-256 */
#define DIGEST_SIZE 32

#include "merkle.h"

struct merkle_root {
    /* trusted root_hash value */
    unsigned char root_hash[DIGEST_SIZE];
    /* size in levels */
    int size;
    /* left branch */
    struct merkle_node *left;
    /* right branch */
    struct merkle_node *right;
};

struct merkle_node {
    /* the node's hash */
    unsigned char val[DIGEST_SIZE];
    /* the node's level, with 0 being the level of merkle_root */
    int level;
    /* left branch */
    struct merkle_node *left;
    /* right branch */
    struct merkle_node *right;
};

void print_tree(struct merkle_root *mr) {
    printf("==== Merkle Tree Root ====\n");
    printf("Tree Size: %d\n", mr->size);
    printf("Root Hash: ");
    print_digest(mr->root_hash);
    printf("\n==========================\n");
    _print_tree(mr->left);
    _print_tree(mr->right);
}

void print_node(struct merkle_node *n) {
    printf("==== Merkle Tree Node ====\n");
    printf("Node on level: %d\n", n->level);
    printf("Node Hash: ");
    print_digest(n->val);
    printf("\n==========================\n");
}

void _print_tree(struct merkle_node *n) {
    /* using morris in-order-traversal */
    while (n) {
        if (n->left == NULL) {
            print_node(n);
            n = n->right;
        } else {
            struct merkle_node *cur = n->left;
            while(cur->right && cur->right != n)
                cur = cur->right;
            if (cur->right == n) {
                cur->right = NULL;
                n = n->right;
            } else {
                print_node(n);
                cur->right = n;
                n = n->left;
            }
        }
    }
}

struct merkle_root* buildTree (struct merkle_root **mr, int num, unsigned char* mn[]) {
    if (num % 2 !=0) {
        // merkle tree needs a number divisible by two as leaf nodes
        puts("Error! Invalid number of nodes provided.");
        return NULL; // caller should check for error
    }
    struct merkle_node **left, **right, **newLeft, **newRight;
    unsigned char concat[2 * DIGEST_SIZE];
    struct merkle_root *root = (struct merkle_root*) malloc(sizeof(struct merkle_root));
    root->size = log2(num);
    int tmpsize = root->size;

    left = (struct merkle_node**) malloc(sizeof(struct merkle_node*) * num/2);
    right = (struct merkle_node**) malloc(sizeof(struct merkle_node*) * num/2);
    for (int i=0; i < num/2; i++) {
        left[i] = (struct merkle_node*) malloc(sizeof(struct merkle_node));
        //SHA256(mn[i], DIGEST_SIZE, left[i]->val);
        memcpy(left[i]->val, mn[i], DIGEST_SIZE); /* inputs already hashed */
        left[i]->level = root->size;
        left[i]->left = NULL;
        left[i]->right = NULL;
    }

    for (int i=0; i < num/2; i++) {
        right[i] = (struct merkle_node*) malloc(sizeof(struct merkle_node));
        //SHA256(mn[num/2 + i], DIGEST_SIZE, right[i]->val);
        memcpy(right[i]->val, mn[num/2+i], DIGEST_SIZE); /* inputs already hashed */
        right[i]->level = root->size;
        right[i]->left = NULL;
        right[i]->right = NULL;
    }

    num /= 2;
    tmpsize -= 1;

    while (num != 1) {
        //printf("Node Count in Current Level: %d\n", num);
        newLeft = (struct merkle_node**) malloc(sizeof(struct merkle_node*) * num/2);
        newRight = (struct merkle_node**) malloc(sizeof(struct merkle_node*) * num/2);

        // computing new left
        for (int i=0; i < num/2; i++) {
            newLeft[i] = create_node(left[i], right[i], tmpsize);
        }

        // computing new right
        for (int i=0; i < num/2; i++) {
            newRight[i] = create_node(left[num/2+i], right[num/2+i], tmpsize);
        }

        free(left);
        free(right);
        left = newLeft;
        right = newRight;
        // halved number of nodes for next round
        num /= 2;
        tmpsize -= 1;
    }

    // now we must build the root
    memcpy(concat, left[0]->val, DIGEST_SIZE);
    memcpy(concat + DIGEST_SIZE, right[0]-> val, DIGEST_SIZE);

    *mr = root;
    root->left = left[0];
    root->right = right[0];

    // hash the root!
    SHA256(concat, 2*DIGEST_SIZE, root->root_hash);
    //free(newLeft);
    //free(newRight);
    free(left);
    free(right);
    return *mr;
}

struct merkle_node* create_node(struct merkle_node* l, struct merkle_node* r, int level) {
    struct merkle_node* n = (struct merkle_node*) malloc(sizeof(struct merkle_node));
    unsigned char concat[2*DIGEST_SIZE];
    n->left = l;
    n->right = r;
    n->level = level;

    memcpy(concat, l->val, DIGEST_SIZE);
    memcpy(concat + DIGEST_SIZE, r->val, DIGEST_SIZE);
    //print_digest(n->val); printf("\n");
    SHA256(concat, DIGEST_SIZE*2, n->val);
    //print_digest(n->val); printf("\n");
    return n;
}

/** this is a recursive solution and is especially bad if we have a large tree :-(
 *  TODO: implement iterative
 **/
void free_tree(struct merkle_root *mr) {
    _free_tree(mr->left);
    _free_tree(mr->right);
    free(mr);
}

void _free_tree(struct merkle_node *n) {
    if (n == NULL) {
        return;
    }
    _free_tree(n->left);
    _free_tree(n->right);
    free(n);
}

void print_digest(unsigned char *dgst) {
    for (int i=0; i < DIGEST_SIZE; i++)
        printf("%02x", dgst[i]);
}

#endif

