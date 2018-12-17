
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

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${PROJECT_SOURCE_DIR}/cmake")
include(AwsCFlags)
include(InstallLogic)
include(TestLibraryPath)

# This is useful for CodeBuild tests since we want to avoid cases where KMS dependencies are missing and
# we are not building aws-encryption-sdk-cpp.
option(FORCE_KMS_KEYRING_BUILD "Fail build if KMS Keyring dependencies are not satisfied")

# End-to-End tests might require special permissions
option(AWS_ENC_SDK_END_TO_END_TESTS "Enable End-to-End tests")


# By default we will try to build KMS Keyring only if we find AwsSdk
if (FORCE_KMS_KEYRING_BUILD)
    message(STATUS "KMS Keyring is required")
    set(KMS_REQUIRED "REQUIRED")
endif()

# for KMS Keyring
find_package(AWSSDK QUIET COMPONENTS core kms)
if (AWSSDK_FOUND)
    option(BUILD_AWS_ENC_SDK_CPP "Build AWS ENC SDK C++ components" ON)
    include_directories(${AWSSDK_INCLUDE_DIR})
    link_directories(${AWSSDK_LIB_DIR})
    message(STATUS "AWSSDK having components core, kms found.")
else()
    find_package(aws-cpp-sdk-core ${KMS_REQUIRED})
    find_package(aws-cpp-sdk-kms ${KMS_REQUIRED})
    if (aws-cpp-sdk-core_FOUND AND aws-cpp-sdk-kms_FOUND)
        option(BUILD_AWS_ENC_SDK_CPP "Build AWS ENC SDK C++ components" ON)
        message(STATUS "aws-cpp-sdk-core and aws-cpp-sdk-kms found.")
    else()
        message(WARNING "AWSSDK having components core and kms not found. KMS Keyring will not be available")
    endif()
endif()


file(GLOB AWS_CRYPTOSDK_CPP_HEADERS
    # Headers subject to API/ABI stability guarantees
    "${CMAKE_CURRENT_SOURCE_DIR}/include/aws/cryptosdk/cpp/*.h"
)

file(GLOB AWS_CRYPTOSDK_CPP_SRC "source/*.cpp")

if (BUILD_AWS_ENC_SDK_CPP)
    set(AWS_ENC_SDK_CPP "aws-encryption-sdk-cpp")
    add_library(aws-encryption-sdk-cpp ${LIBTYPE} ${CORE_CPP_HEADERS} ${AWS_CRYPTOSDK_CPP_SRC})
    set_property(TARGET aws-encryption-sdk-cpp PROPERTY CXX_STANDARD 11)
    # -fvisibility=hidden appears incompatible with the GNU C++ library; this is because in std::basic_string
    # there is a templated (const) static variable, which can be instantiated in multiple libraries, and which
    # is later compared by-address in the basic_string destructor.
    # Normally, the dynamic linker will resolve to a single instance of this static, but -fvisibility=hidden
    # makes our instantiation a local symbol (instead of 'global unique'), which means we end up with multiple
    # instances, and crash when a string is passed across library boundaries and then destroyed.
    aws_set_common_properties(aws-encryption-sdk-cpp NO_VISIBILITY_HIDDEN)

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
    else()
        message(STATUS "End to end tests off")
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

endif(BUILD_AWS_ENC_SDK_CPP)
