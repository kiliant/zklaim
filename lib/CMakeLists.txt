# Only libff needs to be compiled: the parts of libsnark used by zklaim
# (gadgetlib1, r1cs_gg_ppzksnark) are header-only. Building libsnark itself
# would also require Boost and amd64-only assembly (supercop).
set(LIBSNARK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libsnark)
set(LIBFF_DIR ${LIBSNARK_DIR}/depends/libff)

# libff and googletest declare outdated cmake_minimum_required versions (libff:
# 2.8, which CMake >= 4.0 rejects unless a newer policy version is requested)
set(CMAKE_POLICY_VERSION_MINIMUM 3.10)
# CMAKE_POLICY_VERSION_MINIMUM only exists since CMake 4.0. Before that, libff's
# old minimum version leaves CMP0063 unset, and CMake ignores the visibility
# properties set below. libzklaim would then export libff, and a program
# linking both libzklaim and libff could initialize one copy of libff's curve
# parameters while using the other.
set(CMAKE_POLICY_DEFAULT_CMP0063 NEW)

# skip libff's own dependencies, tests and docs
set(IS_LIBFF_PARENT OFF CACHE INTERNAL "")
# The protocol fixes one portable libff encoding: standard decimal field
# elements and uncompressed points. Native limbs and Montgomery residues depend
# on word size and byte order. Keep libff and its header-only consumers aligned.
set(BINARY_OUTPUT OFF CACHE BOOL "Protocol uses portable decimal fields" FORCE)
set(MONTGOMERY_OUTPUT OFF CACHE BOOL "Protocol uses standard field values" FORCE)
set(USE_PT_COMPRESSION OFF CACHE BOOL "Protocol uses uncompressed points" FORCE)
add_subdirectory(${LIBFF_DIR} libff EXCLUDE_FROM_ALL)
# libff is linked statically into libzklaim; keep its symbols out of the
# shared library's interface.
set_target_properties(ff PROPERTIES CXX_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN ON)

if(${CURVE} STREQUAL "BN128")
  # libff's BN128 implementation is based on ate-pairing (x86-64 only)
  add_library(
    zm
    STATIC

    ${LIBFF_DIR}/depends/ate-pairing/src/zm.cpp
    ${LIBFF_DIR}/depends/ate-pairing/src/zm2.cpp
  )

  set_target_properties(zm PROPERTIES CXX_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN ON)

  target_include_directories(
    zm

    PUBLIC
    ${LIBFF_DIR}/depends/ate-pairing/include
    ${LIBFF_DIR}/depends/xbyak
  )
endif()

add_library(snark INTERFACE)
target_compile_definitions(snark INTERFACE NO_PT_COMPRESSION=1)

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
