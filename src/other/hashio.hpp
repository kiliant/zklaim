#ifndef HASHIO_HPP
#define HASHIO_HPP

#include <iostream>

class Hash {
    private:
        unsigned char md[32];
    public:
        friend ostream& operator<<(ostream& os, const Hash& h);
        bool operator==(const Hash& h);
        Hash(unsigned char* toHash, size_t size);
        Hash(unsigned char* md);
};

Hash::Hash(unsigned char* md) {
    memcpy(this->md, md, 32);
}

Hash::Hash(unsigned char* toHash, size_t size) {
    SHA256(toHash, size, this->md);
}

// TODO: NOT timing safe
bool Hash::operator==(const Hash& h) {
    return memcmp(this->md, h.md, 32) == 0;
}

// prints the digest of the hash
ostream& operator<<(ostream& os, const Hash& h) {
    // TODO: not implemented
    for (auto a : h.md) {
        printf("%.2x", a);
    }
    os << endl;
    return os;
}

#endif
