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

find_package(aws-c-common REQUIRED)

# C++ SDK
find_package(AWSSDK)
link_directories("${AWSSDK_LIB_DIR}")

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

CHECK_CXX_COMPILER_FLAG("-Wall" HAS_FLAG_WALL)
CHECK_CXX_COMPILER_FLAG("-pedantic" HAS_FLAG_PEDANTIC)
CHECK_CXX_COMPILER_FLAG("-Werror" HAS_FLAG_WERROR)
CHECK_CXX_COMPILER_FLAG("-Wno-missing-field-initializers" HAS_FLAG_NO_MISSING_FIELD_INITIALIZERS)

if (HAS_FLAG_WALL)
    add_compile_options(-Wall)
endif()
if (HAS_FLAG_PEDANTIC)
    add_compile_options(-pedantic)
endif()
if (HAS_FLAG_WERROR)
    add_compile_options(-Werror)
endif()
if (HAS_FLAG_NO_MISSING_FIELD_INITIALIZERS)
# TODO - this is to avoid warning on the missing 'enabled' field in test case definitions.
# We should find a cleaner way to work around this.
    add_compile_options(-Wno-missing-field-initializers)
endif()

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

include(CTest)
enable_testing()

add_executable(unit-test-suite ${UNIT_TEST_SRC})
target_link_libraries(unit-test-suite ${PROJECT_NAME} ${OPENSSL_LDFLAGS})
set_target_properties(unit-test-suite PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_link_libraries(unit-test-suite aws-encryption-sdk)
target_include_directories(unit-test-suite PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit)

add_executable(test_decrypt "tests/decrypt.c" ${TEST_LIB})
target_link_libraries(test_decrypt ${PROJECT_NAME} ${OPENSSL_LDFLAGS})
set_target_properties(test_decrypt PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_include_directories(test_decrypt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tests/lib)

add_executable(test_decryption_vectors "tests/decryption_vectors.c" ${TEST_LIB})
target_link_libraries(test_decryption_vectors ${PROJECT_NAME} ${OPENSSL_LDFLAGS})
set_target_properties(test_decryption_vectors PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_include_directories(test_decryption_vectors PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tests/lib)

if(CURL_FOUND)
    add_executable(t_encrypt_compat tests/integration/t_encrypt_compat.c)
    set_target_properties(t_encrypt_compat PROPERTIES
        C_STANDARD 99
    )
    target_link_libraries(t_encrypt_compat aws-encryption-sdk ${CURL_LIBRARIES})
    target_include_directories(t_encrypt_compat PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit ${CURL_INCLUDE_DIRS})
    target_sources(t_encrypt_compat PRIVATE ${UNIT_TEST_SRC_CPP})
    add_test(integration_encrypt_compatibility t_encrypt_compat)
endif(AWSSDK_FOUND)

add_test(cipher unit-test-suite cipher)
add_test(header unit-test-suite header)
add_test(materials unit-test-suite materials)
add_test(encrypt unit-test-suite encrypt)

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
