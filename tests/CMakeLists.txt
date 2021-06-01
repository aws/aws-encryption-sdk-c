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

file(GLOB UNIT_TEST_SRC "unit/*.c")
file(GLOB UNIT_TEST_HDRS "*.h")
file(GLOB UNIT_TESTS ${TEST_HDRS} ${TEST_SRC})
file(GLOB TEST_LIB "lib/*.c")

if (VALGRIND_TEST_SUITE)
    set(VALGRIND valgrind --error-exitcode=42 --errors-for-leak-kinds=definite,possible --leak-check=full ${VALGRIND_OPTIONS})
else()
    set(VALGRIND)
endif()

include(CTest)
enable_testing()

add_library(testlib ${LIBTYPE} EXCLUDE_FROM_ALL ${TEST_LIB})
target_link_libraries(testlib ${PROJECT_NAME} ${OPENSSL_LDFLAGS})
set_target_properties(testlib PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_include_directories(testlib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lib)
target_compile_definitions(testlib PRIVATE IN_TESTLIB_BUILD)

add_library(testlib_static STATIC EXCLUDE_FROM_ALL ${TEST_LIB})
target_link_libraries(testlib_static PUBLIC aws-encryption-sdk-test ${OPENSSL_LDFLAGS})
set_target_properties(testlib_static PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_include_directories(testlib_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lib)
target_compile_definitions(testlib_static PRIVATE IN_TESTLIB_BUILD)

add_executable(unit-test-suite ${UNIT_TEST_SRC})
target_link_libraries(unit-test-suite ${OPENSSL_LDFLAGS} testlib_static)
set_target_properties(unit-test-suite PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_include_directories(unit-test-suite PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/unit)

if (REDUCE_TEST_ITERATIONS)
    target_compile_definitions(unit-test-suite PRIVATE REDUCE_TEST_ITERATIONS)
endif()

# This is in the integration tree so its "main" entry point won't clash with the test runner
# Ideally we'd put the cache_test_lib.c file in lib/ as well, but we currently access some
# private symbols (hash_dec_request) from caching_cmm.c, so it can't be linked into
# e.g. tests/decrypt, which deliberately uses the "public" version of the library (which
# hides private symbols like this).
add_executable(test_local_cache_threading "integration/t_local_cache_threading.c" "unit/cache_test_lib.c")
target_include_directories(test_local_cache_threading PRIVATE "unit")
target_link_libraries(test_local_cache_threading aws-encryption-sdk-test ${OPENSSL_LDFLAGS} testlib_static)
set_target_properties(test_local_cache_threading PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_include_directories(test_local_cache_threading PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lib)

add_executable(test_decrypt "decrypt.c")
target_link_libraries(test_decrypt ${PROJECT_NAME} ${OPENSSL_LDFLAGS} testlib)
set_target_properties(test_decrypt PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)

add_executable(test_decryption_vectors "decryption_vectors.c")
target_link_libraries(test_decryption_vectors ${PROJECT_NAME} testlib)
set_target_properties(test_decryption_vectors PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_include_directories(test_decryption_vectors PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lib)

if (REDUCE_TEST_ITERATIONS)
    target_compile_definitions(test_decryption_vectors PRIVATE REDUCE_TEST_ITERATIONS)
endif()

if(AWS_ENC_SDK_END_TO_END_TESTS AND CURL_FOUND)
    add_executable(t_encrypt_compat integration/t_encrypt_compat.c)
    set_target_properties(t_encrypt_compat PROPERTIES
        C_STANDARD 99
    )
    target_link_libraries(t_encrypt_compat PRIVATE aws-encryption-sdk testlib ${CURL_LIBRARIES} ${OPENSSL_CRYPTO_LIBRARY})
    target_include_directories(t_encrypt_compat PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/unit ${CURL_INCLUDE_DIRS})
    target_sources(t_encrypt_compat PRIVATE ${UNIT_TEST_SRC_CPP})
    target_include_directories(t_encrypt_compat PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lib)
    aws_add_test(integration_encrypt_compatibility ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/t_encrypt_compat)
endif(AWS_ENC_SDK_END_TO_END_TESTS AND CURL_FOUND)

aws_add_test(cipher ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite cipher)
aws_add_test(commitment ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite commitment)
aws_add_test(header ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite header)
aws_add_test(materials ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite materials)
aws_add_test(enc_ctx ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite enc_ctx)
aws_add_test(encrypt ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite encrypt)
aws_add_test(framefmt ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite framefmt)
aws_add_test(hkdf ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite hkdf)
aws_add_test(raw_aes_keyring ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite raw_aes_keyring)
aws_add_test(raw_rsa_keyring ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite raw_rsa_keyring)
aws_add_test(multi_keyring ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite multi_keyring)
aws_add_test(signature ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite signature)
aws_add_test(trailing_sig ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite trailing_sig)
aws_add_test(local_cache ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite local_cache)
aws_add_test(caching_cmm ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite caching_cmm)
aws_add_test(keyring_trace ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite keyring_trace)
aws_add_test(max_edks ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite max_edks)

set(TEST_DATA ${CMAKE_CURRENT_SOURCE_DIR}/data)

aws_add_test(decrypt_aes128_hkdf
    ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/test_decrypt ${TEST_DATA}/ct_x_aes128_hkdf.bin ${TEST_DATA}/pt_x_aes128_hkdf.bin)
aws_add_test(decrypt_aes128_hkdf_bad_header
    ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/test_decrypt --xfail ${TEST_DATA}/ct_x_aes128_hkdf_bad_header.bin ${TEST_DATA}/pt_x_aes128_hkdf.bin)
aws_add_test(decrypt_hello
    ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/test_decrypt ${TEST_DATA}/hello.bin ${TEST_DATA}/hello.bin.pt)
aws_add_test(decrypt_hello_tiny
    ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/test_decrypt ${TEST_DATA}/hello.tinyframes.bin ${TEST_DATA}/hello.bin.pt)
aws_add_test(bad_commitment
    ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/test_decrypt --xfail --gcmkey ${TEST_DATA}/ct_bad_commitment.bin ${TEST_DATA}/bad_commitment.pt)
aws_add_test(good_commitment
    ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/test_decrypt --gcmkey ${TEST_DATA}/ct_good_commitment.bin ${TEST_DATA}/good_commitment.pt)
aws_add_test(decryption_vectors ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/test_decryption_vectors)
