# this file is taken from libsnark, where it is licensed under the MIT license

cmake_minimum_required(VERSION 3.13)

project(zklaim C CXX)

enable_testing()

set(CMAKE_EXPORT_COMPILE_COMMANDS "ON")
# libff is linked statically into the shared libzklaim
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default to RelWithDebInfo configuration if no configuration is explicitly specified.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type on single-configuration generators" FORCE)
endif()

set(
  CURVE
  "ALT_BN128"
  CACHE
  STRING
  "Default curve: one of ALT_BN128, BN128, EDWARDS, MNT4, MNT6"
)

set(
  OPT_FLAGS
  ""
  CACHE
  STRING
  "Additional C++ compiler optimization flags, e.g. -march=native"
)

option(
  MULTICORE
  "Enable parallelized execution, using OpenMP"
  OFF
)

option(
  WITH_PROCPS
  "Use procps for memory profiling"
  OFF
)

option(
  VERBOSE
  "Print internal messages"
  OFF
)

if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
  # Common compilation flags and warning configuration
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wfatal-errors -pthread")

  if("${MULTICORE}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp")
  endif()
endif()

add_definitions(-DCURVE_${CURVE})

if(${CURVE} STREQUAL "BN128")
  add_definitions(-DBN_SUPPORT_SNARK=1)
endif()

if("${VERBOSE}")
  add_definitions(-DVERBOSE=1)
endif()

if("${MULTICORE}")
  add_definitions(-DMULTICORE=1)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OPT_FLAGS}")

find_package(PkgConfig REQUIRED)
pkg_check_modules(GCRYPT REQUIRED IMPORTED_TARGET libgcrypt)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

if("${WITH_PROCPS}")
  pkg_check_modules(PROCPS REQUIRED libprocps)
else()
  add_definitions(-DNO_PROCPS)
endif()

include_directories(.)

add_subdirectory(lib)
add_subdirectory(zklaim)
