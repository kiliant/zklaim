#include <gtest/gtest.h>

// include testfiles
#include "zklaim_ecc.cpp"
#include "zklaim.cpp"
#include <gcrypt.h>

int main(int argc, char **argv) {
    gcry_check_version(GCRYPT_VERSION);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
