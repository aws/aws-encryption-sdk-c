
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

set(TEST_DATA ${CMAKE_CURRENT_SOURCE_DIR}/tests/data)

file(GLOB AWS_CRYPTOSDK_CPP_HEADERS
    # Headers subject to API/ABI stability guarantees
    "${CMAKE_CURRENT_SOURCE_DIR}/include/aws/cryptosdk/cpp/*.h"
    )

file(GLOB AWS_CRYPTOSDK_CPP_SRC "source/*.cpp")

set(AWS_ENC_SDK_CPP "aws-encryption-sdk-cpp")
add_library(aws-encryption-sdk-cpp ${LIBTYPE} ${CORE_CPP_HEADERS} ${AWS_CRYPTOSDK_CPP_SRC})
set_property(TARGET aws-encryption-sdk-cpp PROPERTY CXX_STANDARD 11)
# -fvisibility=hidden appears incompatible with the GNU C++ library; this is because in std::basic_string
# there is a templated (const) static variable, which can be instantiated in multiple libraries, and which
# is later compared by-address in the basic_string destructor.
# Normally, the dynamic linker will resolve to a single instance of this static, but -fvisibility=hidden
# makes our instantiation a local symbol (instead of 'global unique'), which means we end up with multiple
# instances, and crash when a string is passed across library boundaries and then destroyed.
aws_cryptosdk_set_common_properties(aws-encryption-sdk-cpp NO_VISIBILITY_HIDDEN)

target_include_directories(aws-encryption-sdk-cpp PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/aws-encryption-sdk-cpp/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/noninst_include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated/include>
    $<INSTALL_INTERFACE:include>
    )
set_target_properties(aws-encryption-sdk-cpp PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(aws-encryption-sdk-cpp PUBLIC AWS::aws-c-common aws-cpp-sdk-kms aws-cpp-sdk-core aws-encryption-sdk)
aws_install_target(TARGET aws-encryption-sdk-cpp HEADERS ${AWS_CRYPTOSDK_CPP_HEADERS} HEADER_ROOTS ${CMAKE_CURRENT_SOURCE_DIR}/include)

if (VALGRIND_TEST_SUITE)
    target_compile_definitions(aws-encryption-sdk-cpp PRIVATE VALGRIND_TESTS=1)
endif()

include(CTest)
enable_testing()

file(GLOB TEST_LIB "tests/lib/*.cpp")
file(GLOB TEST_LIB_HEADERS "tests/lib/*.h")

add_library(testlibcpp ${LIBTYPE} EXCLUDE_FROM_ALL ${TEST_LIB_HEADERS} ${TEST_LIB})
target_link_libraries(testlibcpp PUBLIC aws-encryption-sdk-cpp testlib)
set_target_properties(testlibcpp PROPERTIES CXX_STANDARD 11 C_STANDARD 99)
target_include_directories(testlibcpp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/lib
    ${PROJECT_SOURCE_DIR}/tests/unit
    ${PROJECT_SOURCE_DIR}/tests/lib $<INSTALL_INTERFACE:include>)
target_compile_definitions(testlibcpp PRIVATE -DIN_TESTLIB_CPP_BUILD)

if (AWS_ENC_SDK_END_TO_END_TESTS)
    message(STATUS "End to end tests on")
    add_executable(t_integration_kms_keyring tests/integration/t_integration_kms_keyring.cpp)
    target_link_libraries(t_integration_kms_keyring testlibcpp)
    target_include_directories(t_integration_kms_keyring PUBLIC ${PROJECT_SOURCE_DIR}/tests/lib
        ${PROJECT_SOURCE_DIR}/tests/unit
        ${PROJECT_SOURCE_DIR}/tests/integration
        $<INSTALL_INTERFACE:include>
        )
    set_target_properties(t_integration_kms_keyring PROPERTIES CXX_STANDARD 11 C_STANDARD 99)
    aws_add_test(integration_kms_mk ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/t_integration_kms_keyring)

    add_executable(t_commitment_known_answer tests/integration/t_commitment_known_answer.cpp)
    target_link_libraries(t_commitment_known_answer testlibcpp)
    target_include_directories(t_commitment_known_answer PUBLIC ${PROJECT_SOURCE_DIR}/tests/lib
        ${PROJECT_SOURCE_DIR}/tests/unit
        ${PROJECT_SOURCE_DIR}/tests/integration
        $<INSTALL_INTERFACE:include>
        )
    set_target_properties(t_commitment_known_answer PROPERTIES CXX_STANDARD 11 C_STANDARD 99)
    aws_add_test(commitment_known_answer ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/t_commitment_known_answer ${TEST_DATA}/commitment_known_answer_tests.json)

    add_executable(t_max_encrypted_data_keys tests/integration/t_max_encrypted_data_keys.cpp)
    target_link_libraries(t_max_encrypted_data_keys testlibcpp)
    target_include_directories(t_max_encrypted_data_keys PUBLIC ${PROJECT_SOURCE_DIR}/tests/lib
        ${PROJECT_SOURCE_DIR}/tests/unit
        ${PROJECT_SOURCE_DIR}/tests/integration
        $<INSTALL_INTERFACE:include>
        )
    set_target_properties(t_max_encrypted_data_keys PROPERTIES CXX_STANDARD 11 C_STANDARD 99)
    aws_add_test(integration_max_edks ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/t_max_encrypted_data_keys)
else()
    message(STATUS "End to end tests off")
endif()

if (AWS_ENC_SDK_KNOWN_GOOD_TESTS)
    message(STATUS "Static known good tests on")
    find_path(JSON_C_INCLUDE_DIR json.h
        HINTS ${JSON_C_INCLUDEDIR} ${JSON_C_INCLUDE_DIR} PATH_SUFFIXES json-c json)
    find_library(JSON_C_LIBRARY NAMES json-c libjson-c
        HINTS ${JSON_C_LIBDIR} ${JSON_C_LIBRARY_DIR})
    set(JSON_C_LIBRARY ${JSON_C_LIBRARY})
    set(JSON_C_INCLUDE_DIR ${JSON_C_INCLUDE_DIR})
    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(JSON_C DEFAULT_MSG JSON_C_LIBRARY JSON_C_INCLUDE_DIR)
    
    file(GLOB TEST_VECTORS "tests/test_vectors/*.cpp")
    add_library(test_vectors EXCLUDE_FROM_ALL ${TEST_VECTORS})
    target_link_libraries(test_vectors aws-encryption-sdk-cpp testlibcpp json-c)
    set_target_properties(test_vectors PROPERTIES CXX_STANDARD 11 C_STANDARD 99)
    target_include_directories(test_vectors PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tests/lib
        ${PROJECT_SOURCE_DIR}/tests/lib $<INSTALL_INTERFACE:include>)
    add_executable(static_test_vectors tests/test_vectors/static_test_vectors.cpp ${TEST_VECTORS})
    target_link_libraries(static_test_vectors test_vectors)
    set_target_properties(static_test_vectors PROPERTIES CXX_STANDARD 11 C_STANDARD 99)
    target_include_directories(static_test_vectors PUBLIC ${PROJECT_SOURCE_DIR}/tests/lib
        ${PROJECT_SOURCE_DIR}/tests/unit
        ${PROJECT_SOURCE_DIR}/tests/integration
        $<INSTALL_INTERFACE:include>
        )

    # Also unzip the test vectors from the aws-encryption-sdk-test-vectors submodule
    # TODO-RS: If desired, we can use a custom target to avoid doing this
    # on every build when the zip hasn't changed.
    message(STATUS "Unzipping test vectors")
    set(TEST_VECTORS_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/test-vectors)
    file(MAKE_DIRECTORY ${TEST_VECTORS_DIRECTORY})
    execute_process(COMMAND ${CMAKE_COMMAND} -E tar xf ${AWS_ENC_SDK_TEST_VECTORS_ZIP}
        WORKING_DIRECTORY ${TEST_VECTORS_DIRECTORY}
        RESULT_VARIABLE _exit_code)
    if(${_exit_code})
        message(FATAL_ERROR "Unzipping test vectors failed")
    endif()

    aws_add_test(static_test_vectors ${CMAKE_CURRENT_BINARY_DIR}/static_test_vectors ${TEST_VECTORS_DIRECTORY})
else()
    message(STATUS "Static known good tests off")
endif()

file(GLOB test_sources FOLLOW_SYMLINKS tests/unit/*.cpp)
foreach(test_cpp ${test_sources})
    get_filename_component(TEST_NAME ${test_cpp} NAME_WE)
    add_executable(${TEST_NAME} ${test_cpp})
    target_link_libraries(${TEST_NAME} testlibcpp)
    target_include_directories(${TEST_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tests/lib
        ${PROJECT_SOURCE_DIR}/tests/unit
        ${PROJECT_SOURCE_DIR}/tests/integration
        $<INSTALL_INTERFACE:include>
        )
    set_target_properties(${TEST_NAME} PROPERTIES CXX_STANDARD 11 C_STANDARD 99)

    aws_add_test(${TEST_NAME}.test ${VALGRIND} ${CMAKE_CURRENT_BINARY_DIR}/${TEST_NAME})
endforeach()
