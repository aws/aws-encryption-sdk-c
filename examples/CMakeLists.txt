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

message(STATUS "Building C examples")
file(GLOB example_c_sources FOLLOW_SYMLINKS *.c)
foreach (source ${example_c_sources})
    get_filename_component(EXAMPLE_NAME ${source} NAME_WE)
    add_executable(${EXAMPLE_NAME} ${source})
    target_link_libraries(${EXAMPLE_NAME} PRIVATE AWS::aws-c-common aws-encryption-sdk)
    set_target_properties(${EXAMPLE_NAME} PROPERTIES C_STANDARD 99)
endforeach ()

# KMS keyring CMakeLists.txt is a sibling to this CMakeLists.txt so variables set
# set in there are not carried over to this file. At the moment we are repeating
# the same AWS SDK C++ detection logic for whether to build the C++ examples here.
# TODO: possible refactor?
if (SKIP_KMS_KEYRING_BUILD)
    message(STATUS "Skipping KMS Keyring build, so skipping C++ examples also")
else()
    if (FORCE_KMS_KEYRING_BUILD)
        message(STATUS "KMS Keyring is required")
	set(KMS_REQUIRED "REQUIRED")
    endif()

    find_package(AWSSDK QUIET COMPONENTS core kms)
    if (AWSSDK_FOUND)
        option(BUILD_CPP_EXAMPLES "Build C++ examples" ON)
        include_directories(${AWSSDK_INCLUDE_DIR})
        link_directories(${AWSSDK_LIB_DIR})
        message(STATUS "AWSSDK having components core, kms found.")
    else()
        find_package(aws-cpp-sdk-core ${KMS_REQUIRED})
        find_package(aws-cpp-sdk-kms ${KMS_REQUIRED})
        if (aws-cpp-sdk-core_FOUND AND aws-cpp-sdk-kms_FOUND)
            option(BUILD_CPP_EXAMPLES "Build C++ examples" ON)
            message(STATUS "aws-cpp-sdk-core and aws-cpp-sdk-kms found.")
        else()
            message(WARNING "C++ examples not built")
        endif()
    endif()

    if (BUILD_CPP_EXAMPLES)
        message(STATUS "Building C++ examples")
        file(GLOB example_cpp_sources FOLLOW_SYMLINKS *.cpp)
        foreach (source ${example_cpp_sources})
            get_filename_component(EXAMPLE_NAME ${source} NAME_WE)
            add_executable(${EXAMPLE_NAME} ${source})
            target_link_libraries(${EXAMPLE_NAME} PRIVATE AWS::aws-c-common aws-cpp-sdk-kms aws-cpp-sdk-core aws-encryption-sdk aws-encryption-sdk-cpp)
            set_target_properties(${EXAMPLE_NAME} PROPERTIES CXX_STANDARD 11 C_STANDARD 99)
        endforeach ()
    endif(BUILD_CPP_EXAMPLES)

endif(SKIP_KMS_KEYRING_BUILD)

