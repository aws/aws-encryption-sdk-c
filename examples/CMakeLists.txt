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

include(CTest)
enable_testing()

message(STATUS "Building C examples")
file(GLOB example_c_sources FOLLOW_SYMLINKS *.c)
foreach (source ${example_c_sources})
    get_filename_component(EXAMPLE_NAME ${source} NAME_WE)
    add_executable(${EXAMPLE_NAME} ${source})
    target_link_libraries(${EXAMPLE_NAME} PRIVATE AWS::aws-c-common aws-encryption-sdk)
    set_target_properties(${EXAMPLE_NAME} PROPERTIES C_STANDARD 99)
endforeach ()

aws_add_test(example_raw_aes_keyring ${CMAKE_CURRENT_BINARY_DIR}/raw_aes_keyring
  ${CMAKE_CURRENT_SOURCE_DIR}/example_data/aes_256_key)
aws_add_test(example_raw_rsa_keyring ${CMAKE_CURRENT_BINARY_DIR}/raw_rsa_keyring
  ${CMAKE_CURRENT_SOURCE_DIR}/example_data/rsa_private_key.pem ${CMAKE_CURRENT_SOURCE_DIR}/example_data/rsa_public_key.pem)

if (BUILD_AWS_ENC_SDK_CPP)
    message(STATUS "Building C++ examples")
    file(GLOB example_cpp_sources FOLLOW_SYMLINKS *.cpp)
    foreach (source ${example_cpp_sources})
        get_filename_component(EXAMPLE_NAME ${source} NAME_WE)
        add_executable(${EXAMPLE_NAME} ${source})
        target_link_libraries(${EXAMPLE_NAME} PRIVATE AWS::aws-c-common aws-cpp-sdk-kms aws-cpp-sdk-core aws-encryption-sdk aws-encryption-sdk-cpp)
        set_target_properties(${EXAMPLE_NAME} PROPERTIES CXX_STANDARD 11 C_STANDARD 99)
    endforeach ()

    if (AWS_ENC_SDK_END_TO_END_TESTS)
        list(APPEND example_env_vars
            AWS_ENC_SDK_EXAMPLE_KEY_ARN
            AWS_ENC_SDK_EXAMPLE_KEY_ARN_US_WEST_2
            AWS_ENC_SDK_EXAMPLE_KEY_ARN_EU_CENTRAL_1)
        foreach (env_var ${example_env_vars})
            if (NOT DEFINED ENV{${env_var}})
                message(SEND_ERROR ${env_var} " environment variable not set; some examples may fail")
            endif()
        endforeach()

        aws_add_test(example_caching_cmm ${CMAKE_CURRENT_BINARY_DIR}/caching_cmm
          $ENV{AWS_ENC_SDK_EXAMPLE_KEY_ARN} example hello world)
        aws_add_test(example_file_streaming ${CMAKE_CURRENT_BINARY_DIR}/file_streaming
          $ENV{AWS_ENC_SDK_EXAMPLE_KEY_ARN} ${CMAKE_CURRENT_SOURCE_DIR}/example_data/hello_world.txt)
        aws_add_test(example_kms_discovery ${CMAKE_CURRENT_BINARY_DIR}/kms_discovery
          $ENV{AWS_ENC_SDK_EXAMPLE_KEY_ARN_US_WEST_2} $ENV{AWS_ENC_SDK_EXAMPLE_KEY_ARN_EU_CENTRAL_1})
        aws_add_test(example_multi_keyring ${CMAKE_CURRENT_BINARY_DIR}/multi_keyring
          $ENV{AWS_ENC_SDK_EXAMPLE_KEY_ARN} ${CMAKE_CURRENT_SOURCE_DIR}/example_data/aes_256_key)
        aws_add_test(example_string ${CMAKE_CURRENT_BINARY_DIR}/string
          $ENV{AWS_ENC_SDK_EXAMPLE_KEY_ARN})
    endif()
else()
    message(STATUS "Build of C++ components was skipped, so skipping C++ examples also")
endif()
