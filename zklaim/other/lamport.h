#ifndef LAMPORT_H
#define LAMPORT_H

#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

struct lamport_sig {
    unsigned char pubkey[16384];
    unsigned char sig[8192];
} __attribute__((__packed__));

/**
 * create a Lamport Diffie OT-Signature Scheme Public/Private KeyPair
 * memory region of privkey MUST be at least MSGLEN * MSGLEN * 2 / 8B
 * memory region of pubkey  MUST be at least MSGLEN * MSGLEN * 2 / 8B
 */
int create_private_key(unsigned char* privkey, unsigned char* pubkey);

/**
 * sign a message using a LD-OTS private key
 */
int sign(unsigned char* msg, unsigned char* privkey, unsigned char* sig);

/**
 * verify a LD-OTS-signed message using the message, a given (and trusted!)
 * public key and a signature
 * WARNING: this method is currently not timing safe
 */
int verify(unsigned char* msg, unsigned char* pubkey, unsigned char* sig);


#endif //LAMPORT_H
