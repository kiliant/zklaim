include_directories(
    .
    tests
    tests/hashes
)

include_directories(${CMAKE_SOURCE_DIR}/zklaim)

#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
add_library(
    zklaim

    SHARED
    libsnark_wrapper.cpp
    zklaim_ecc.c
    zklaim_hash.c
    zklaim.c
)

target_link_libraries(zklaim snark gcrypt)
set_target_properties(zklaim PROPERTIES LINKER_LANGUAGE C)

#add_executable(
#  main
#
#  main.cpp
#  zklaim.c
#)
#target_link_libraries(
#  main
#
#  snark
#)

#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")

add_executable(
    main

    main.c
)

add_executable(
    main_benchmark

    main_benchmark.c
)

set_target_properties(main PROPERTIES LINKER_LANGUAGE C)

target_link_libraries(main zklaim gcrypt)

target_link_libraries(main_benchmark zklaim gcrypt pthread)

add_executable(
    bttestc

    tests/bttest.cpp)

target_link_libraries(bttestc snark zklaim gcrypt gtest)

target_include_directories(
  bttestc

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libff
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

target_include_directories(
  zklaim

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libff
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

install(
    DIRECTORY "" DESTINATION "include/zklaim"
    FILES_MATCHING
    PATTERN "*.h"
    PATTERN "tests" EXCLUDE
    PATTERN "other" EXCLUDE
)

install(
    TARGETS zklaim
    DESTINATION lib
)

#add_executable(lamport_test tests/lamport_test.cpp)
#target_link_libraries(lamport_test ssl crypto gtest)

target_include_directories(
  main

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)


# for now managing tests in a custom target
# using cmake for globally enabling testing pulls in also the tests from snarklib
# TODO: find a way to specify custom test suites
# enable_testing()
# add_test( testname Exename arg1 arg2 ... )
add_custom_target(
    bttest

    #COMMAND lamport_test
    COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND bttestc
)

