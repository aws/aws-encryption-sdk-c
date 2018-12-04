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

# On windows, we can't use rpath-like mechanisms to set library search paths.
# This cmake function will configure a target to use an appropriate PATH
# at ctest time, allowing it to find its dependencies.

# Further, cmake doesn't let us access target output directories, or do
# anything that depends on debug vs release, prior to execution of the cmake
# "generator" (which is too late to configure CTest). We end up needing some hacks here
# to specify the right output directories. Yes, this is fragile. Hopefully cmake
# eventually provides a better mechanism for this.

function(add_path_from_imported_lib path_var imported_target)
    set(test_path ${${path_var}})

    # This is an awful hack; we don't have a way of telling which configuration
    # (release vs debug) is being built, so we'll just throw all versions of the imported
    # SDK onto the path
    get_property(awssdk_configs TARGET ${imported_target} PROPERTY IMPORTED_CONFIGURATIONS)
    foreach(config IN ITEMS ${awssdk_configs})
        get_property(sdk_lib_file TARGET ${imported_target} PROPERTY IMPORTED_LOCATION_${config})
        message(STATUS "add_path_from_imported_lib target ${imported_target} config ${config} libfile ${sdk_lib_file}")
        get_filename_component(sdk_basedir ${sdk_lib_file} DIRECTORY)
        list(INSERT test_path 0 ${sdk_basedir})
    endforeach()

    set(${path_var} ${test_path} PARENT_SCOPE)
endfunction()

function(add_raw_lib_paths path_var)
    set(test_path ${${path_var}})

    foreach(lib IN ITEMS ${ARGN})
        get_filename_component(basedir ${lib} DIRECTORY)
        list(INSERT test_path 0 ${basedir})
    endforeach()

    set(${path_var} ${test_path} PARENT_SCOPE)
endfunction()

function(set_test_library_path testname)
    if(WIN32) # includes win64
        set(test_path "$ENV{PATH}")

        if(TARGET aws-cpp-sdk-core)
            add_path_from_imported_lib(test_path aws-cpp-sdk-core)
        endif()
        add_path_from_imported_lib(test_path AWS::aws-c-common)

        add_raw_lib_paths(test_path ${CURL_LIBRARIES})
        add_raw_lib_paths(test_path ${OPENSSL_CRYPTO_LIBRARY})

        # As mentioned above, cmake simultaneously generates Debug and Release configurations for MSVC generators.
        # However, generator expression expansion does not happen for the ctest configuration, so it's not possible
        # to teach ctest which configuration was actually built (even when invoked via msbuild on RUN_TESTS.vcxproj).
        # We'll just shove both paths onto the PATH and hope for the best...
        foreach(possible_config IN ITEMS Release Debug .)
            list(INSERT test_path 0 ${PROJECT_BINARY_DIR}/${possible_config})
            list(INSERT test_path 0 ${PROJECT_BINARY_DIR}/tests/${possible_config})
            list(INSERT test_path 0 ${CMAKE_CURRENT_BINARY_DIR}/${possible_config})
        endforeach()

        list(REMOVE_DUPLICATES test_path)

        string(REPLACE ";" "\\;" test_path "${test_path}")

        set_tests_properties(${testname} PROPERTIES ENVIRONMENT "PATH=${test_path}")
    endif(WIN32)
endfunction()

macro(aws_add_test testname)
    add_test(${testname} ${ARGN})
    set_test_library_path(${testname})
endmacro()