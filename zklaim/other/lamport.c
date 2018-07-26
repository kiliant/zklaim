#ifndef LAMPORT_C
#define LAMPORT_C

/* the length of the messages we want to sign IN BITS */
#define MSGLEN 256

#include "lamport.h"

int create_private_key(unsigned char* privkey, unsigned char* pubkey)
{
    ssize_t am = MSGLEN*MSGLEN*2/8;
    // TODO: introduce "better" source of randomness, possibly cheap-hashing /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    // fill private key data (= pre-image) with randomness
    if (am != read(fd, privkey, am))
    {
        printf("error while reading random");
        exit(EXIT_FAILURE);
    }

    // hash every element of the 2*MSGLEN vector
    for (int i = 0; i < 2*MSGLEN; i++) {
        SHA256((privkey + i*MSGLEN/8), MSGLEN/8, (pubkey + i*MSGLEN/8));
    }

    close(fd);
    return EXIT_SUCCESS;
}

int sign(unsigned char* msg, unsigned char* privkey, unsigned char* sig)
{
    unsigned char c;
    unsigned char m;
    size_t off = MSGLEN/8; /* one element in bytes */

    // we have to iterate over all bytes of the message
    for (size_t i = 0; i < off; i++) {
        // c is a byte!
        c = *(msg + i);
        m = 0b10000000;
        for (size_t k = 0; k < 8; k++) {
            if ((c & m) != 0x0) {
                // bit at position m was 1
                //*(sig+i*MSGLEN) = *(privkey+(i+k)*2*MSGLEN+MSGLEN);
                memcpy(sig+(i*8+k)*off, privkey+(i*8+k)*2*off+off, off);
            } else {
                //*(sig+i*MSGLEN) = *(privkey+(i+k)*2*MSGLEN);
                memcpy(sig+(i*8+k)*off, privkey+(i*8+k)*2*off, off);
            }
            m = m >> 1;
        }
    }

    return EXIT_SUCCESS;
}

int verify(unsigned char* msg, unsigned char* pubkey, unsigned char* sig)
{
    // !!!!!!!!!!!!!!
    // TODO!!!!!!!!!!
    // memcmp is NOOOT timing-safe, but may be sufficient in our usecase.
    unsigned char c;
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    unsigned char m;

    // bytewise
    for (int i = 0; i < MSGLEN/8; i++) {
        c = *(msg + i);
        m = 0b10000000;
        // bitwise
        for (int k = 0; k < 8; k++) {
            // calculate correct hash
            SHA256(sig+(i*8+k)*MSGLEN/8, MSGLEN/8, hash);
            if ((c & m) != 0x0) {
                // bit at position m was 1
                if (memcmp(pubkey+(i*8+k)*2*MSGLEN/8 + MSGLEN/8, hash, MSGLEN/8) != 0) {
                    return EXIT_FAILURE;
                }
            } else {
                // bit at position m was 0
                if (memcmp(pubkey+(i*8+k)*2*MSGLEN/8, hash, MSGLEN/8) != 0) {
                    return EXIT_FAILURE;
                }
            }
            m = m >> 1;
        }
    }
    return EXIT_SUCCESS;
}

#endif //LAMPORT_C
