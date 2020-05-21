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

cmake_minimum_required (VERSION 3.9)
project (aws-encryption-sdk LANGUAGES C)

if (UNIX AND NOT APPLE)
    include(GNUInstallDirs)
elseif(NOT DEFINED CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR "lib")
endif()

include(CTest)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Make sure we can pick up Cmake modules installed by dependencies
# both when they are in the CMAKE_INSTALL_PREFIX directory
# and in the CMAKE_PREFIX_PATH list.
list(APPEND CMAKE_MODULE_PATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/cmake")
foreach(prefix ${CMAKE_PREFIX_PATH})
    list(APPEND CMAKE_MODULE_PATH "${prefix}/${CMAKE_INSTALL_LIBDIR}/cmake")
endforeach(prefix)

# Including AwsSharedLibSetup depends on aws-c-common being installed already.
# Putting this ahead of that include line for a more meaningful error when missing.
find_package(aws-c-common CONFIG REQUIRED)

include(AwsCryptosdkCFlags)
include(AwsSharedLibSetup)
include(InstallLogic)
include(TestLibraryPath)
include(CheckLibraryExists)
include(CodeCoverageFlags)

include(FindOpenSSL)

set(PROJECT_NAME aws-encryption-sdk)

# Version number of the SDK to be consumed by C code and Doxygen
set(MAJOR 1)
set(MINOR 1)
set(PATCH 0)

# Compiler feature tests and feature flags
set(USE_ASM TRUE
    CACHE BOOL "Enable use of inline assembler, if supported by the compiler and platform")

set(REDUCE_TEST_ITERATIONS FALSE
    CACHE BOOL "Reduce the number of iterations done on some exhaustive tests. This is particularly helpful when running under valgrind")

set(BUILD_SHARED_LIBS FALSE
    CACHE BOOL "Build aws-encryption-sdk-c as a shared library")

option(AWS_ENC_SDK_END_TO_END_TESTS "Enable end-to-end tests. If set to FALSE (the default), runs local tests only.")
if(AWS_ENC_SDK_END_TO_END_TESTS)
    include(FindCURL)
endif()

option(PERFORM_HEADER_CHECK "Performs compile-time checks that each header can be included independently. Requires a C++ compiler.")

option(VALGRIND_TEST_SUITE "Run the test suite under valgrind")
set(VALGRIND_OPTIONS "--suppressions=${CMAKE_CURRENT_SOURCE_DIR}/valgrind.suppressions" CACHE STRING "Additional options to pass to valgrind")

CHECK_C_SOURCE_COMPILES("
    int main() { return __builtin_expect(0, 0); }
    " HAVE_BUILTIN_EXPECT)

# Generate includable header files exposing build-time configuration
set(GENERATED_INCLUDE "${CMAKE_CURRENT_BINARY_DIR}/generated/include")
set(GENERATED_CONFIG_HEADER "${GENERATED_INCLUDE}/aws/cryptosdk/private/config.h")
set(GENERATED_VERSION_HEADER "${GENERATED_INCLUDE}/aws/cryptosdk/version.h")

configure_file("include/aws/cryptosdk/version.h.in"
               ${GENERATED_VERSION_HEADER}
               ESCAPE_QUOTES)

file(GLOB AWS_CRYPTOSDK_HEADERS
# Headers subject to API/ABI stability guarantees
     "include/aws/cryptosdk/*.h"
     ${GENERATED_VERSION_HEADER}
)

file(GLOB AWS_CRYPTOSDK_SRC
    "source/*.c"
)

if (PERFORM_HEADER_CHECK)
    set(HEADERS_TO_CHECK ${AWS_CRYPTOSDK_HEADERS})
    add_subdirectory(cmake/header-tester)
endif()

# Also expose git revision information in user-agent
include(GitRevision)
FindGitRevision(git_revision)
if(git_revision STREQUAL "")
    set(AWS_CRYPTOSDK_PRIVATE_GITVERSION "" CACHE INTERNAL "")
else()
    set(AWS_CRYPTOSDK_PRIVATE_GITVERSION "-${git_revision}" CACHE INTERNAL "")
endif()


CHECK_LIBRARY_EXISTS("rt" "clock_gettime" "" HAVE_LIBRT)
if(HAVE_LIBRT)
   set(PLATFORM_LIBS ${PLATFORM_LIBS} "rt")
endif()

CHECK_LIBRARY_EXISTS("pthread" "pthread_mutex_lock" "" HAVE_LIBPTHREAD)
if(HAVE_LIBRT)
   set(PLATFORM_LIBS ${PLATFORM_LIBS} "pthread")
endif()

if(BUILD_SHARED_LIBS)
    set(LIBTYPE SHARED)
else()
    set(LIBTYPE STATIC)
endif()

add_library(${PROJECT_NAME} ${LIBTYPE} ${AWS_CRYPTOSDK_HEADERS} ${AWS_CRYPTOSDK_SRC})
set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
aws_cryptosdk_set_common_properties(${PROJECT_NAME})

target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/noninst_include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated/include>
    $<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(${PROJECT_NAME} PRIVATE ${PLATFORM_LIBS} ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(${PROJECT_NAME} PUBLIC AWS::aws-c-common)

# Some of our unit tests need to access private symbols. Build a static library for their use.
# We'll use the shared lib for integration tests.
add_library(aws-encryption-sdk-test EXCLUDE_FROM_ALL STATIC ${AWS_CRYPTOSDK_HEADERS} ${AWS_CRYPTOSDK_SRC})
set_target_properties(aws-encryption-sdk-test PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
aws_cryptosdk_set_common_properties(aws-encryption-sdk-test)

target_include_directories(aws-encryption-sdk-test PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/noninst_include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated/include>
    $<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIR}>
)

target_link_libraries(aws-encryption-sdk-test PRIVATE ${PLATFORM_LIBS} ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(aws-encryption-sdk-test PUBLIC AWS::aws-c-common)
target_compile_definitions(aws-encryption-sdk-test PRIVATE AWS_CRYPTOSDK_TEST_STATIC=)
target_compile_definitions(aws-encryption-sdk-test PUBLIC AWS_ENCRYPTION_SDK_FORCE_STATIC)

include(CodeCoverageTargets)

# Installation logic
aws_install_target(
    TARGET ${CMAKE_PROJECT_NAME}
    HEADERS ${AWS_CRYPTOSDK_HEADERS}
    HEADER_ROOTS ${GENERATED_INCLUDE} ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# BUILD_AWS_ENC_SDK_CPP defined as ON = force build of C++ components
# BUILD_AWS_ENC_SDK_CPP defined as OFF = skip build of C++ components
# BUILD_AWS_ENC_SDK_CPP undefined = detect whether to build C++ components
if (DEFINED BUILD_AWS_ENC_SDK_CPP AND NOT BUILD_AWS_ENC_SDK_CPP)
    message(STATUS "Skipping build of AWS Encryption SDK C++ components")
else()
    find_package(AWSSDK QUIET COMPONENTS core kms)
    if (AWSSDK_FOUND)
        include_directories(${AWSSDK_INCLUDE_DIR})
        link_directories(${AWSSDK_LIB_DIR})
        message(STATUS "AWSSDK C++ having components core, kms found.")
        option(BUILD_AWS_ENC_SDK_CPP "Build AWS ENC SDK C++ components" ON)
    else()
        # This fallback logic is needed on Windows
        find_package(aws-cpp-sdk-core)
        find_package(aws-cpp-sdk-kms)
        if (aws-cpp-sdk-core_FOUND AND aws-cpp-sdk-kms_FOUND)
            message(STATUS "aws-cpp-sdk-core and aws-cpp-sdk-kms found.")
            option(BUILD_AWS_ENC_SDK_CPP "Build AWS ENC SDK C++ components" ON)
        else()
            if (BUILD_AWS_ENC_SDK_CPP)
                message(FATAL_ERROR "AWSSDK C++ components core and kms not found but BUILD_AWS_ENC_SDK_CPP was set to ON.")
            else()
                message(WARNING "AWSSDK C++ components core and kms not found. Will not build AWS Encryption SDK C++ components.")
            endif()
        endif()
    endif()
endif()

if (BUILD_AWS_ENC_SDK_CPP)
    enable_language(CXX)
    add_subdirectory(aws-encryption-sdk-cpp)
endif()

add_subdirectory(tests)

# Generate the config header at the end, after we've finished feature probing
set(AWS_CRYPTOSDK_P_HAVE_LIBPTHREAD ${HAVE_LIBPTHREAD} CACHE INTERNAL "")
set(AWS_CRYPTOSDK_P_HAVE_LIBRT ${HAVE_LIBRT} CACHE INTERNAL "")
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
                COMMAND ${CMAKE_COMMAND} -E env MAJOR=${MAJOR} MINOR=${MINOR} PATCH=${PATCH} ${DOXYGEN_EXECUTABLE} ${DOXYGEN_CONFIG_FILE_GENERATED}
                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                COMMENT "Generating Doxygen documentation"
                VERBATIM)
    else (DOXYGEN_FOUND)
        message(FATAL_ERROR "Doxygen not found. Documentation can't be generated")
    endif (DOXYGEN_FOUND)
endif(BUILD_DOC)

# Examples
add_subdirectory(examples)
