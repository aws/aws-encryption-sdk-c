# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# ESDK TestServer Language_Server for C. Built only with -DBUILD_TEST_SERVER=ON;
# POSIX-only (sockets + threads).

enable_language(CXX)
find_package(Threads REQUIRED)

add_library(esdk-test-server-lib STATIC bridge.cpp cbor.cpp http.cpp server.cpp)
aws_cryptosdk_set_common_properties(esdk-test-server-lib NO_VISIBILITY_HIDDEN)
set_target_properties(
    esdk-test-server-lib PROPERTIES LINKER_LANGUAGE CXX CXX_STANDARD 11 CXX_STANDARD_REQUIRED ON)
target_include_directories(esdk-test-server-lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(esdk-test-server-lib PUBLIC aws-encryption-sdk AWS::aws-c-common Threads::Threads)

add_executable(esdk-test-server main.cpp)
aws_cryptosdk_set_common_properties(esdk-test-server NO_VISIBILITY_HIDDEN)
set_target_properties(esdk-test-server PROPERTIES LINKER_LANGUAGE CXX CXX_STANDARD 11 CXX_STANDARD_REQUIRED ON)
target_link_libraries(esdk-test-server PRIVATE esdk-test-server-lib)

include(CTest)
enable_testing()

foreach(TEST_NAME test_server_cbor test_server_protocol)
    add_executable(${TEST_NAME} tests/${TEST_NAME}.cpp)
    aws_cryptosdk_set_common_properties(${TEST_NAME} NO_VISIBILITY_HIDDEN)
    set_target_properties(${TEST_NAME} PROPERTIES LINKER_LANGUAGE CXX CXX_STANDARD 11 CXX_STANDARD_REQUIRED ON)
    target_link_libraries(${TEST_NAME} PRIVATE esdk-test-server-lib)
    aws_add_test(${TEST_NAME} ${CMAKE_CURRENT_BINARY_DIR}/${TEST_NAME})
endforeach()
