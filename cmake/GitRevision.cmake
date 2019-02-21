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

function(FindGitRevision variable_name)
    execute_process(COMMAND git describe --always --match "release-v*"
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        RESULT_VARIABLE _exit_code
        OUTPUT_VARIABLE _description
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if(${_exit_code} OR "${_description}" STREQUAL "")
        message(STATUS "Unable to find git revision")
        SET(${variable_name} "" PARENT_SCOPE)
        return()
    endif()

    message(STATUS "Git revision description: ${_description}")

    if (${_description} MATCHES "^(release-)?v[^-]+$")
        message(STATUS "On tagged release; not appending revision suffix")
        set(_revision "")
    else()
        string(REGEX REPLACE "^.*-([0-9]+-g[0-9a-f]+)$" "\\1" _revision ${_description})
    endif()

    # Check for a dirty working copy now
    execute_process(COMMAND git diff --shortstat HEAD
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        RESULT_VARIABLE _exit_code
        OUTPUT_VARIABLE _shortstat
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if(${_exit_code})
        message(WARNING "git diff --shortstat failed")
        set(_dirty TRUE)
    elseif(NOT "${_shortstat}" STREQUAL "")
        set(_dirty TRUE)
    else()
        set(_dirty FALSE)
    endif()

    if(${_dirty})
        set(_revision "${_revision}-dirty")
        string(REGEX REPLACE "^-" "" _revision "${_revision}")
    endif()

    set(${variable_name} ${_revision} PARENT_SCOPE)
    message(STATUS "Git revision suffix: ${_revision}")
endfunction()
