if (VALGRIND_TEST_SUITE)
    set(VALGRIND valgrind --error-exitcode=42 --errors-for-leak-kinds=definite,possible --leak-check=full ${VALGRIND_OPTIONS})
else()
    set(VALGRIND)
endif()

include(CTest)
enable_testing()

add_library(testlib EXCLUDE_FROM_ALL ${TEST_LIB})
target_link_libraries(testlib ${PROJECT_NAME} ${OPENSSL_LDFLAGS})
set_target_properties(testlib PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_include_directories(testlib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lib)

add_executable(unit-test-suite ${UNIT_TEST_SRC})
target_link_libraries(unit-test-suite aws-encryption-sdk-test ${OPENSSL_LDFLAGS} testlib)
set_target_properties(unit-test-suite PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_include_directories(unit-test-suite PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/unit)

if (REDUCE_TEST_ITERATIONS)
    target_compile_definitions(unit-test-suite PRIVATE REDUCE_TEST_ITERATIONS)
endif()

add_executable(test_decrypt "decrypt.c" ${TEST_LIB})
target_link_libraries(test_decrypt ${PROJECT_NAME} ${OPENSSL_LDFLAGS} testlib)
set_target_properties(test_decrypt PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)

add_executable(test_decryption_vectors "decryption_vectors.c" ${TEST_LIB})
target_link_libraries(test_decryption_vectors ${PROJECT_NAME})
set_target_properties(test_decryption_vectors PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_include_directories(test_decryption_vectors PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lib)

if (REDUCE_TEST_ITERATIONS)
    target_compile_definitions(test_decryption_vectors PRIVATE REDUCE_TEST_ITERATIONS)
endif()

if(CURL_FOUND)
    add_executable(t_encrypt_compat integration/t_encrypt_compat.c ${TEST_LIB})
    set_target_properties(t_encrypt_compat PROPERTIES
        C_STANDARD 99
    )
    target_link_libraries(t_encrypt_compat PRIVATE aws-encryption-sdk ${CURL_LIBRARIES} ${OPENSSL_CRYPTO_LIBRARY})
    target_include_directories(t_encrypt_compat PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/unit ${CURL_INCLUDE_DIRS})
    target_sources(t_encrypt_compat PRIVATE ${UNIT_TEST_SRC_CPP})
    target_include_directories(t_encrypt_compat PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lib)
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
add_test(local_cache ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite local_cache)
add_test(caching_cmm ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/unit-test-suite caching_cmm)

set(TEST_DATA ${CMAKE_CURRENT_SOURCE_DIR}/data)

add_test(decrypt_aes128_hkdf
    ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/test_decrypt ${TEST_DATA}/ct_x_aes128_hkdf.bin ${TEST_DATA}/pt_x_aes128_hkdf.bin)
add_test(decrypt_aes128_hkdf_bad_header
    ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/test_decrypt --xfail ${TEST_DATA}/ct_x_aes128_hkdf_bad_header.bin ${TEST_DATA}/pt_x_aes128_hkdf.bin)
add_test(decrypt_hello
    ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/test_decrypt ${TEST_DATA}/hello.bin ${TEST_DATA}/hello.bin.pt)
add_test(decrypt_hello_tiny
    ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/test_decrypt ${TEST_DATA}/hello.tinyframes.bin ${TEST_DATA}/hello.bin.pt)
add_test(decryption_vectors ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/test_decryption_vectors)