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

set(PROJECT_NAME aws-encryption-sdk)

file(GLOB AWS_CRYPTOSDK_HEADERS
     "include/aws/cryptosdk/*.h"
)

file(GLOB AWS_CRYPTOSDK_PRIV_HEADERS
     "include/aws/cryptosdk/private/*.h"
)

file(GLOB AWS_CRYPTOSDK_SRC
    "source/*.c"
)

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
    $<INSTALL_INTERFACE:include>)
  
target_link_libraries(aws-encryption-sdk ${PLATFORM_LIBS})

file(GLOB TEST_SRC "tests/*.c")
file(GLOB TEST_HDRS "tests/*.h")
file(GLOB TESTS ${TEST_HDRS} ${TEST_SRC})
  
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/tests)
add_executable(aws-encryption-sdk-tests ${TESTS})
target_link_libraries(aws-encryption-sdk-tests aws-encryption-sdk)
set_target_properties(aws-encryption-sdk-tests PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)

include(CTest)
enable_testing()

add_test(test_a aws-encryption-sdk-tests test_a)
add_test(test_b aws-encryption-sdk-tests test_b)

install (FILES ${AWS_CRYPTOSDK_HEADERS} DESTINATION "${CMAKE_INSTALL_PREFIX}/include/aws/encryption-sdk")
install (
         TARGETS ${PROJECT_NAME} EXPORT ${PROJECT_NAME}-config
         ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
         LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
         COMPONENT library     
)

export(TARGETS ${PROJECT_NAME} FILE aws-encryption-sdk-config.cmake)
install(EXPORT ${PROJECT_NAME}-config DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/aws-encryption-sdk/cmake/")

