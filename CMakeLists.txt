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
include(CheckLibraryExists)
include(CheckCXXSourceCompiles)

# TODO: Static link?
include(FindOpenSSL)

set(PROJECT_NAME aws-encryption-sdk)

set(CMAKE_BUILD_TYPE Debug)

# Compiler feature tests and feature flags
set(USE_ASM TRUE
    CACHE BOOL "Enable use of inline assembler, if supported by the compiler and platform")

set(SPECTRE_MITIGATIONS TRUE
    CACHE BOOL "Attempt to mitigate SPECTRE attacks, at a potential performance cost")

set(AWS_C_COMMON_PATH "" CACHE STRING "Path to the directory containing aws-c-common-config.cmake")
include(${AWS_C_COMMON_PATH}/aws-c-common-config.cmake)

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
# Headers not subject to API stability (but subject to ABI stability)
# These typically include internal macros and helpers used in static inline functions
     "include/aws/cryptosdk/private/*.h"
)

file(GLOB AWS_CRYPTOSDK_PRIV_HEADERS
# Headers not installed with the library
     "noninst_include/aws/cryptosdk/private/*.h"
)

file(GLOB AWS_CRYPTOSDK_SRC
    "source/*.c"
)

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

add_library(aws-encryption-sdk ${LIBTYPE} ${CORE_HEADERS} ${CORE_SRC})
set_target_properties(aws-encryption-sdk PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
set(CMAKE_C_FLAGS_DEBUGOPT "")

if(CMAKE_BUILD_TYPE STREQUAL "" OR CMAKE_BUILD_TYPE MATCHES DEBUG)
    target_compile_definitions(aws-encryption-sdk PRIVATE "-DDEBUG_BUILD")
endif()

target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/noninst_include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated/include>
    $<INSTALL_INTERFACE:include>
    ${OPENSSL_INCLUDE_DIR}
)
  
target_link_libraries(aws-encryption-sdk ${PLATFORM_LIBS} aws-c-common ${OPENSSL_CRYPTO_LIBRARY})

file(GLOB UNIT_TEST_SRC "tests/unit/*.c")
file(GLOB UNIT_TEST_HDRS "tests/*.h")
file(GLOB UNIT_TESTS ${TEST_HDRS} ${TEST_SRC})
file(GLOB TEST_LIB "tests/lib/*.c")
  
add_executable(unit-test-suite ${UNIT_TEST_SRC})
target_link_libraries(unit-test-suite ${PROJECT_NAME} ${OPENSSL_LDFLAGS})
set_target_properties(unit-test-suite PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_include_directories(unit-test-suite PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit${CMAKE_CURRENT_SOURCE_DIR}/source)

add_executable(test_decrypt "tests/decrypt.c" ${TEST_LIB})
target_link_libraries(test_decrypt ${PROJECT_NAME} ${OPENSSL_LDFLAGS})
set_target_properties(test_decrypt PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_include_directories(test_decrypt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tests/lib)

add_executable(test_decryption_vectors "tests/decryption_vectors.c" ${TEST_LIB})
target_link_libraries(test_decryption_vectors ${PROJECT_NAME} ${OPENSSL_LDFLAGS})
set_target_properties(test_decryption_vectors PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_include_directories(test_decryption_vectors PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tests/lib)

include(CTest)
enable_testing()

add_test(cipher unit-test-suite cipher)
add_test(header unit-test-suite header)
add_test(materials unit-test-suite materials)

set(TEST_DATA ${CMAKE_CURRENT_SOURCE_DIR}/tests/data)

add_test(decrypt_aes128_hkdf
    test_decrypt ${TEST_DATA}/ct_x_aes128_hkdf.bin ${TEST_DATA}/pt_x_aes128_hkdf.bin)
add_test(decrypt_aes128_hkdf_bad_header
    test_decrypt --xfail ${TEST_DATA}/ct_x_aes128_hkdf_bad_header.bin ${TEST_DATA}/pt_x_aes128_hkdf.bin)
add_test(decrypt_hello
    test_decrypt ${TEST_DATA}/hello.bin ${TEST_DATA}/hello.bin.pt)
add_test(decrypt_hello_tiny
    test_decrypt ${TEST_DATA}/hello.tinyframes.bin ${TEST_DATA}/hello.bin.pt)
add_test(decryption_vectors test_decryption_vectors)

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

set(AWS_CRYPTOSDK_P_HAVE_LIBPTHREAD ${HAVE_LIBPTHREAD} BOOL)
set(AWS_CRYPTOSDK_P_HAVE_LIBRT ${HAVE_LIBRT} BOOL)
set(AWS_CRYPTOSDK_P_USE_X86_64_ASM ${USE_X86_64_ASM} BOOL)
set(AWS_CRYPTOSDK_P_SPECTRE_MITIGATIONS ${SPECTRE_MITIGATIONS} BOOL)
set(AWS_CRYPTOSDK_P_HAVE_BUILTIN_EXPECT ${HAVE_BUILTIN_EXPECT} BOOL)

configure_file("include/aws/cryptosdk/private/config.h.in"
               ${GENERATED_CONFIG_HEADER}
               ESCAPE_QUOTES)
