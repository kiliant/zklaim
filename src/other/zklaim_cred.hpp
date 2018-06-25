#ifndef ZKLAIM_CRED_HPP
#define ZKLAIM_CRED_HPP

#include "hashio.hpp"
#include <inttypes.h>

//////////////////////////////////////////////////////////////////
// zklaim definition of credential types goes here
//////////////////////////////////////////////////////////////////

#define ZKLAIM_CRED_TEST 1
#define ZKLAIM_CRED_TEST_PL // size of payload of TEST type in uint32_t multiples

// test credential
/*
 * employeeID: uint32_t (open to the public)
 * employeeLevel: uint32*8 (32 byte hash)
 */

//////////////////////////////////////////////////////////////////
// zklaim definition of structs
//////////////////////////////////////////////////////////////////

/*struct ZKLAIM_credential {
    uint32_t issuer; // the issuer public key / ID
    uint32_t subject; // the subject public key / ID
    uint32_t type; // the credential type (see definitions in zklaim_cred.h)
    size_t size; // the size of the credential
    uint64_t not_after;
    uint64_t not_before;
    uint64_t issued_at;
}*/

// the sig contains hashes over all attributes and the signature over the hash of all hashes itself
class ZKLAIM_sig {

};

// specifics are subclassed from ZKLAIM_credential
class ZKLAIM_credential {
    public:
        // TODO: move to private?
        uint32_t issuer;
        uint32_t subject;
        uint32_t type;
        size_t size;
        uint64_t not_after;
        uint64_t not_before;
        uint64_t issued_at;
        ZKLAIM_sig *sig;
        void print();
        ZKLAIM_credential(uint32_t issuer, uint32_t subject, uint32_t type, size_t size, uint64_t not_after,
                uint64_t not_before, uint64_t issued_at, ZKLAIM_sig *sig);
    private:
        // TODO: needed?
};

ZKLAIM_credential::ZKLAIM_credential(uint32_t issuer, uint32_t subject, uint32_t type, size_t size, uint64_t not_after,
        uint64_t not_before, uint64_t issued_at, ZKLAIM_sig *sig) {
    this->issuer = issuer;
    this->subject = subject;
    this->type = type;
    this->size = size;
    this->not_after = not_after;
    this->not_before = not_before;
    this->issued_at = issued_at;
    this->sig = sig;
}

void ZKLAIM_credential::print(void) {
    using namespace std;
    cout << "Issuer: " << issuer << endl;
    cout << "Subject: " << subject << endl;
    cout << "Type: " << type << endl;
    cout << "Size: " << size << endl;
    cout << "Not_After: " << not_after << endl;
    cout << "Not_Before: " << not_before << endl;
    cout << "Issued_At: " << issued_at << endl;
}

class ZKLAIM_test_credential : public ZKLAIM_credential {
    public:
        void print();
        ZKLAIM_test_credential(uint32_t issuer, uint32_t subject, uint32_t type, size_t size, uint64_t not_after,
            uint64_t not_before, uint64_t issued_at, ZKLAIM_sig *sig, uint64_t salt, uint32_t employeeID, uint32_t employeeLvl);
    private:
        // TODO: data structure organisation?
        // TODO: store pre-images in one data structure
        // these are all pre-images
        uint32_t employeeID;
        uint64_t salt; // the salt for all hashes, disclosed by authority and private!
        std::map<std::string, Hash> hashes;
        uint32_t employeeLvl; // the preimage to employeeLvl hash
};

ZKLAIM_test_credential::ZKLAIM_test_credential(uint32_t issuer, uint32_t subject, uint32_t type, size_t size, uint64_t not_after,
        uint64_t not_before, uint64_t issued_at, ZKLAIM_sig *sig, uint64_t salt, uint32_t employeeID, uint32_t employeeLvl)
    : ZKLAIM_credential(issuer, subject, type, size, not_after, not_before, issued_at, sig) {
    this->salt = salt;
    this->employeeID = employeeID;
    this->employeeLvl = employeeLvl;
    this->hashes.insert(std::make_pair("employeeLvl", Hash((unsigned char*) &this->employeeLvl, 4)));
}

void ZKLAIM_test_credential::print(void) {
    using namespace std;
    cout << endl << "============= PRINTING CREDENTIAL =============" << endl;
    ZKLAIM_credential::print();
    cout << "employeeID: " << this->employeeID << endl;
    printf("salt: 0x%" PRIx64 "\n", this->salt);
    cout << "[private] EmployeeLvl_pre!: " << this->employeeLvl << endl;
    auto h = this->hashes.find("employeeLvl");
    cout << "employeeLvl hash: " << h->second << endl;
    cout << "===============================================" << endl << endl;
}

#endif
