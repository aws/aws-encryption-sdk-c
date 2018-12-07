# Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

# This file is originally from the aws-c-common project

include(CheckCCompilerFlag)
include(CheckIncludeFile)

# This function will set all common flags on a target
# Options:
#  NO_WGNU: Disable -Wgnu
#  NO_WEXTRA: Disable -Wextra
#  NO_PEDANTIC: Disable -pedantic
function(aws_set_common_properties target)
    set(options NO_WGNU NO_WEXTRA NO_PEDANTIC NO_VISIBILITY_HIDDEN)
    cmake_parse_arguments(SET_PROPERTIES "${options}" "" "" ${ARGN})

    if(MSVC)
        list(APPEND AWS_C_FLAGS /W3 /WX)
        # /volatile:iso relaxes some implicit memory barriers that MSVC normally applies for volatile accesses
        # Since we want to be compatible with user builds using /volatile:iso, use it for the tests.
        list(APPEND AWS_C_FLAGS /volatile:iso)

        # MSVC complains if we use C99-standard functions like strerror() instead of their
        # proprietary "secure" versions such as strerror_s. Since we need to be portable, disable
        # those warnings.
        add_definitions("-D_CRT_SECURE_NO_WARNINGS")

        # Suppress various warnings
        # TODO: Fix these?
        list(APPEND AWS_C_FLAGS /wd4820) # Warns for struct padding
        list(APPEND AWS_C_FLAGS /wd4255) # Warns for missing (void) in function definitions
        list(APPEND AWS_C_FLAGS /wd4388) # Signed/unsigned comparisons
        list(APPEND AWS_C_FLAGS /wd4267 /wd4242 /wd4244) # Narrowing implicit conversions of int types
        list(APPEND AWS_C_FLAGS /wd4245) # Implicit sign extension, unsigned to signed conversion
        list(APPEND AWS_C_FLAGS /wd4221) # obj = { .foo = nonconstant() }

        # MSVC warnings about C99 standard stuff
        list(APPEND AWS_C_FLAGS /wd4204) # arr = { 0, 1, 2 } initializers

        # MSVC warnings that we don't want
        list(APPEND AWS_C_FLAGS /wd4706) # assignment within conditional
        list(APPEND AWS_C_FLAGS /wd5045) # "Compiler will insert spectre mitigations if /Qspectre specified"
    else()
        list(APPEND AWS_C_FLAGS -Wall -Werror)

        if(NOT SET_PROPERTIES_NO_WEXTRA)
            list(APPEND AWS_C_FLAGS -Wextra)
        endif()

        if(NOT SET_PROPERTIES_NO_PEDANTIC)
            list(APPEND AWS_C_FLAGS -pedantic)
        endif()

        # Warning disables always go last to avoid future flags re-enabling them
        list(APPEND AWS_C_FLAGS -Wno-long-long)
        list(APPEND AWS_C_FLAGS -Wno-missing-field-initializers)
    endif(MSVC)

    if(NOT SET_PROPERTIES_NO_WGNU)
        check_c_compiler_flag(-Wgnu HAS_WGNU)
        if(HAS_WGNU)
            # -Wgnu-zero-variadic-macro-arguments results in a lot of false positives
            list(APPEND AWS_C_FLAGS -Wgnu -Wno-gnu-zero-variadic-macro-arguments)
        endif()
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL "" OR CMAKE_BUILD_TYPE MATCHES Debug)
        list(APPEND AWS_C_DEFINES -DDEBUG_BUILD)
    endif()

    if(BUILD_SHARED_LIBS)
        set(target_name_tmp ${target})
        string(TOUPPER ${target_name_tmp} target_name_tmp)
        string(REGEX REPLACE "^AWS-C-" "AWS-" target_name ${target_name_tmp})
        string(REPLACE "-" "_" target_name_tmp ${target_name_tmp})

        # This define configures the headers to export symbols on both windows and linux
        list(APPEND AWS_C_DEFINES -D${target_name_tmp}_EXPORTS)
        # This define, conversely, configures the headers to import symbols from the DLL
        # on windows. On Linux it has no effect.
        target_compile_definitions(${target} PUBLIC -D${target_name_tmp}_SHARED)
        # Also, make sure our other targets also define the _SHARED symbol
        add_definitions(-D${target_name_tmp}_SHARED)

        if(NOT MSVC AND NOT ${SET_PROPERTIES_NO_VISIBILITY_HIDDEN})
            # Avoid exporting symbols we don't mark as exported
            # Note that this behavior is the default on windows.
            list(APPEND AWS_C_FLAGS -fvisibility=hidden)
        endif()
    endif()

    target_compile_options(${target} PRIVATE ${AWS_C_FLAGS})
    target_compile_definitions(${target} PRIVATE ${AWS_C_DEFINES})
    set_target_properties(${target} PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
endfunction()
