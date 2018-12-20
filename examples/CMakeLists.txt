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

option(AWS_ENC_SDK_EXAMPLES "Enable building of examples")

if (AWS_ENC_SDK_EXAMPLES)
    message(STATUS "Building code examples")
    find_package(AWSSDK QUIET COMPONENTS core kms)
    file(GLOB example_sources FOLLOW_SYMLINKS *.cpp)
    foreach (source ${example_sources})
        get_filename_component(EXAMPLE_NAME ${source} NAME_WE)
        add_executable(${EXAMPLE_NAME} ${source})
        target_link_libraries(${EXAMPLE_NAME} PRIVATE AWS::aws-c-common aws-cpp-sdk-kms aws-cpp-sdk-core aws-encryption-sdk aws-encryption-sdk-cpp)
        set_target_properties(${EXAMPLE_NAME} PROPERTIES CXX_STANDARD 11 C_STANDARD 99)
    endforeach ()
else ()
    message(STATUS "Code examples not built")
endif ()
