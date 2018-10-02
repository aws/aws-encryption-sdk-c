# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use
# this file except in compliance with the License. A copy of the License is
# located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.
#

cmake_minimum_required (VERSION 3.1)
project (aws-encryption-sdk)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(AwsCFlags)

include(CheckLibraryExists)
include(CheckCXXSourceCompiles)
include(CheckCXXCompilerFlag)

# TODO: Static link?
include(FindOpenSSL)
# For tests
include(FindCURL)

set(PROJECT_NAME aws-encryption-sdk)

# Compiler feature tests and feature flags
set(USE_ASM TRUE
    CACHE BOOL "Enable use of inline assembler, if supported by the compiler and platform")

set(SPECTRE_MITIGATIONS TRUE
    CACHE BOOL "Attempt to mitigate SPECTRE attacks, at a potential performance cost")

set(REDUCE_TEST_ITERATIONS FALSE
    CACHE BOOL "Reduce the number of iterations done on some exhaustive tests. This is particularly helpful when running under valgrind")

set(BUILD_SHARED_LIBS FALSE
    CACHE BOOL "Build aws-encryption-sdk-c as a shared library")

option(PERFORM_HEADER_CHECK "Performs compile-time checks that each header can be included independently. Requires a C++ compiler.")

option(VALGRIND_TEST_SUITE "Run the test suite under valgrind")
set(VALGRIND_OPTIONS "" CACHE STRING "Additional options to pass to valgrind")

if (VALGRIND_TEST_SUITE)
    set(VALGRIND valgrind --error-exitcode=42 --errors-for-leak-kinds=definite,possible --leak-check=full ${VALGRIND_OPTIONS})
else()
    set(VALGRIND)
endif()

find_package(aws-c-common CONFIG REQUIRED)

if(USE_ASM)
    CHECK_CXX_SOURCE_COMPILES("
    int main() {
        __asm__(\"xor %%rax, %%rax\":::);
        return 0;
    }"
    USE_X86_64_ASM
    )
endif()

CHECK_CXX_SOURCE_COMPILES("
    int main() { return __builtin_expect(0, 0); }
" HAVE_BUILTIN_EXPECT)

file(GLOB AWS_CRYPTOSDK_HEADERS
# Headers subject to API/ABI stability guarantees
     "include/aws/cryptosdk/*.h"
)

file(GLOB AWS_CRYPTOSDK_PRIV_HEADERS
# Headers not installed with the library
     "include/aws/cryptosdk/private/*.h"
)

file(GLOB AWS_CRYPTOSDK_SRC
    "source/*.c"
)

if (PERFORM_HEADER_CHECK)
    set(HEADERS_TO_CHECK ${AWS_CRYPTOSDK_HEADERS})
    add_subdirectory(cmake/header-tester)
endif()

# Generate an includable header file exposing build-time configuration
set(GENERATED_CONFIG_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated/include/aws/cryptosdk/private/config.h")

CHECK_LIBRARY_EXISTS("rt" "clock_gettime" "" HAVE_LIBRT)
if(HAVE_LIBRT)
   set(PLATFORM_LIBS ${PLATFORM_LIBS} "rt")
endif()

CHECK_LIBRARY_EXISTS("pthread" "pthread_mutex_lock" "" HAVE_LIBPTHREAD)
if(HAVE_LIBRT)
   set(PLATFORM_LIBS ${PLATFORM_LIBS} "pthread")
endif()

file(GLOB CORE_HEADERS
    ${AWS_CRYPTOSDK_HEADERS}
    ${AWS_CRYPTOSDK_PRIV_HEADERS}
    ${GENERATED_CONFIG_HEADER}
)

file(GLOB CORE_SRC
    ${AWS_CRYPTOSDK_SRC}
)

if(BUILD_SHARED_LIBS)
    set(LIBTYPE SHARED)
else()
    set(LIBTYPE STATIC)
endif()

add_library(${PROJECT_NAME} ${LIBTYPE} ${CORE_HEADERS} ${CORE_SRC})
set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
aws_set_common_properties(${PROJECT_NAME})

target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/noninst_include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated/include>
    $<INSTALL_INTERFACE:include>
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(${PROJECT_NAME} PRIVATE ${PLATFORM_LIBS} ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(${PROJECT_NAME} PUBLIC aws-c-common)

# Some of our unit tests need to access private symbols. Build a static library for their use.
# We'll use the shared lib for integration tests.
add_library(aws-encryption-sdk-test EXCLUDE_FROM_ALL STATIC ${CORE_HEADERS} ${CORE_SRC})
set_target_properties(aws-encryption-sdk-test PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
aws_set_common_properties(aws-encryption-sdk-test)

target_include_directories(aws-encryption-sdk-test PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/noninst_include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated/include>
    $<INSTALL_INTERFACE:include>
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(aws-encryption-sdk-test PRIVATE ${PLATFORM_LIBS} ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(aws-encryption-sdk-test PUBLIC aws-c-common)



file(GLOB UNIT_TEST_SRC "tests/unit/*.c")
file(GLOB UNIT_TEST_HDRS "tests/*.h")
file(GLOB UNIT_TESTS ${TEST_HDRS} ${TEST_SRC})
file(GLOB TEST_LIB "tests/lib/*.c")

add_subdirectory(aws-encryption-sdk-cpp)

include(CTest)
enable_testing()

add_library(testlib EXCLUDE_FROM_ALL ${TEST_LIB})
target_link_libraries(testlib ${PROJECT_NAME} ${OPENSSL_LDFLAGS})
set_target_properties(testlib PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_include_directories(testlib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tests/lib)

add_executable(unit-test-suite ${UNIT_TEST_SRC})
target_link_libraries(unit-test-suite aws-encryption-sdk-test ${OPENSSL_LDFLAGS} testlib)
set_target_properties(unit-test-suite PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_include_directories(unit-test-suite PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit)

if (REDUCE_TEST_ITERATIONS)
    target_compile_definitions(unit-test-suite PRIVATE REDUCE_TEST_ITERATIONS)
endif()

add_executable(test_decrypt "tests/decrypt.c" ${TEST_LIB})
target_link_libraries(test_decrypt ${PROJECT_NAME} ${OPENSSL_LDFLAGS} testlib)
set_target_properties(test_decrypt PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)

add_executable(test_decryption_vectors "tests/decryption_vectors.c" ${TEST_LIB})
target_link_libraries(test_decryption_vectors ${PROJECT_NAME})
set_target_properties(test_decryption_vectors PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_include_directories(test_decryption_vectors PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tests/lib)

if (REDUCE_TEST_ITERATIONS)
    target_compile_definitions(test_decryption_vectors PRIVATE REDUCE_TEST_ITERATIONS)
endif()

if(CURL_FOUND)
    add_executable(t_encrypt_compat tests/integration/t_encrypt_compat.c ${TEST_LIB})
    set_target_properties(t_encrypt_compat PROPERTIES
        C_STANDARD 99
    )
    target_link_libraries(t_encrypt_compat PRIVATE aws-encryption-sdk ${CURL_LIBRARIES} ${OPENSSL_CRYPTO_LIBRARY})
    target_include_directories(t_encrypt_compat PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit ${CURL_INCLUDE_DIRS})
    target_sources(t_encrypt_compat PRIVATE ${UNIT_TEST_SRC_CPP})
    target_include_directories(t_encrypt_compat PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tests/lib)
    add_test(integration_encrypt_compatibility ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/t_encrypt_compat)
endif(CURL_FOUND)

add_test(cipher ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite cipher)
add_test(header ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite header)
add_test(materials ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite materials)
add_test(enc_context ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite enc_context)
add_test(encrypt ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite encrypt)
add_test(hkdf ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite hkdf)
add_test(raw_aes_keyring ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite raw_aes_keyring)
add_test(raw_rsa_keyring ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite raw_rsa_keyring)
add_test(multi_keyring ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite multi_keyring)
add_test(signature ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite signature)
add_test(trailing_sig ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite trailing_sig)

set(TEST_DATA ${CMAKE_CURRENT_SOURCE_DIR}/tests/data)

add_test(decrypt_aes128_hkdf
    ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/test_decrypt ${TEST_DATA}/ct_x_aes128_hkdf.bin ${TEST_DATA}/pt_x_aes128_hkdf.bin)
add_test(decrypt_aes128_hkdf_bad_header
    ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/test_decrypt --xfail ${TEST_DATA}/ct_x_aes128_hkdf_bad_header.bin ${TEST_DATA}/pt_x_aes128_hkdf.bin)
add_test(decrypt_hello
    ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/test_decrypt ${TEST_DATA}/hello.bin ${TEST_DATA}/hello.bin.pt)
add_test(decrypt_hello_tiny
    ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/test_decrypt ${TEST_DATA}/hello.tinyframes.bin ${TEST_DATA}/hello.bin.pt)
add_test(decryption_vectors ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/test_decryption_vectors)

install (FILES ${AWS_CRYPTOSDK_HEADERS} DESTINATION "${CMAKE_INSTALL_PREFIX}/include/aws/encryption-sdk")
install (
         TARGETS ${PROJECT_NAME} EXPORT ${PROJECT_NAME}-config
         ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
         LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
         COMPONENT library
)

export(TARGETS ${PROJECT_NAME} FILE aws-encryption-sdk-config.cmake)
install(EXPORT ${PROJECT_NAME}-config DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/aws-encryption-sdk/cmake/")

# Generate the header at the end, after we've finished feature probing

set(AWS_CRYPTOSDK_P_HAVE_LIBPTHREAD ${HAVE_LIBPTHREAD} CACHE INTERNAL "")
set(AWS_CRYPTOSDK_P_HAVE_LIBRT ${HAVE_LIBRT} CACHE INTERNAL "")
set(AWS_CRYPTOSDK_P_USE_X86_64_ASM ${USE_X86_64_ASM} CACHE INTERNAL "")
set(AWS_CRYPTOSDK_P_SPECTRE_MITIGATIONS ${SPECTRE_MITIGATIONS} CACHE INTERNAL "")
set(AWS_CRYPTOSDK_P_HAVE_BUILTIN_EXPECT ${HAVE_BUILTIN_EXPECT} CACHE INTERNAL "")

configure_file("include/aws/cryptosdk/private/config.h.in"
               ${GENERATED_CONFIG_HEADER}
               ESCAPE_QUOTES)

# Documentation
option(BUILD_DOC "Build documentation" OFF)
if (BUILD_DOC)
    find_package(Doxygen)
    if (DOXYGEN_FOUND)
        set(DOXYGEN_CONFIG_FILE_IN ${CMAKE_CURRENT_SOURCE_DIR}/doxygen/doxygen.config.in)
        set(DOXYGEN_CONFIG_FILE_GENERATED ${CMAKE_CURRENT_BINARY_DIR}/doxygen/doxygen.config)
        configure_file(${DOXYGEN_CONFIG_FILE_IN} ${DOXYGEN_CONFIG_FILE_GENERATED} @ONLY)
        add_custom_target(doc_doxygen ALL
                COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_CONFIG_FILE_GENERATED}
                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                COMMENT "Generating Doxygen documentation"
                VERBATIM)
    else (DOXYGEN_FOUND)
        message(FATAL_ERROR "Doxygen not found. Documentation can't be generated")
    endif (DOXYGEN_FOUND)
endif(BUILD_DOC)
