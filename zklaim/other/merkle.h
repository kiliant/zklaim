#ifndef MERKLE_H
#define MERKLE_H

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <string.h>
#include <math.h> // link with -lm

struct merkle_root;

struct merkle_node;

void print_tree(struct merkle_root *mr);

void _print_tree(struct merkle_node *n);

struct merkle_root* buildTree(struct merkle_root **mr, int num, unsigned char* mn[]);

struct merkle_node* create_node(struct merkle_node* l, struct merkle_node* r, int level);

void free_tree(struct merkle_root *mr);

void _free_tree(struct merkle_node *n);

void print_digest(unsigned char *dgst);

#endif
