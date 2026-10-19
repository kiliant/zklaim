# Only libff needs to be compiled: the parts of libsnark used by zklaim
# (gadgetlib1, r1cs_gg_ppzksnark) are header-only. Building libsnark itself
# would also require Boost and amd64-only assembly (supercop).
set(LIBSNARK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libsnark)
set(LIBFF_DIR ${LIBSNARK_DIR}/depends/libff)

# libff and googletest declare outdated cmake_minimum_required versions (libff:
# 2.8, which CMake >= 4.0 rejects unless a newer policy version is requested)
set(CMAKE_POLICY_VERSION_MINIMUM 3.10)

# skip libff's own dependencies, tests and docs
set(IS_LIBFF_PARENT OFF CACHE INTERNAL "")
add_subdirectory(${LIBFF_DIR} libff EXCLUDE_FROM_ALL)

if(${CURVE} STREQUAL "BN128")
  # libff's BN128 implementation is based on ate-pairing (x86-64 only)
  add_library(
    zm
    STATIC

    ${LIBFF_DIR}/depends/ate-pairing/src/zm.cpp
    ${LIBFF_DIR}/depends/ate-pairing/src/zm2.cpp
  )

  target_include_directories(
    zm

    PUBLIC
    ${LIBFF_DIR}/depends/ate-pairing/include
    ${LIBFF_DIR}/depends/xbyak
  )
endif()

add_library(snark INTERFACE)

target_include_directories(
  snark

  INTERFACE
  ${LIBSNARK_DIR}
  ${LIBSNARK_DIR}/depends/libfqfft
)

# libff prints field elements through GMP's C++ stream operators
find_library(GMPXX_LIBRARY NAMES gmpxx libgmpxx)

target_link_libraries(snark INTERFACE ff ${GMPXX_LIBRARY})

set(BUILD_GMOCK OFF)
set(INSTALL_GTEST OFF)
add_subdirectory(googletest EXCLUDE_FROM_ALL)
