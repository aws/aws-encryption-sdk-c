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

if (CODE_COVERAGE_ENABLE)
    # By default, the code coverage output goes into the "html/" subdirectory in the binary files area
    if (NOT DEFINED CODE_COVERAGE_OUTPUT_DIR)
        set(CODE_COVERAGE_OUTPUT_DIR ${CMAKE_BINARY_DIR}/html)
        set(CODE_COVERAGE_INFO_FILE ${CODE_COVERAGE_OUTPUT_DIR}/coverage.info)
    endif()
    target_link_libraries(${PROJECT_NAME} PRIVATE --coverage)
    find_program(CODE_COVERAGE_LCOV lcov)
    find_program(CODE_COVERAGE_GENHTML genhtml)
    add_custom_target(coverage
            COMMAND ${CMAKE_COMMAND} -E make_directory ${CODE_COVERAGE_OUTPUT_DIR}
            COMMAND ${CODE_COVERAGE_LCOV} --directory ${CMAKE_BINARY_DIR} --capture --output-file ${CODE_COVERAGE_INFO_FILE}
            COMMAND ${CODE_COVERAGE_GENHTML} --output-directory ${CODE_COVERAGE_OUTPUT_DIR} ${CODE_COVERAGE_INFO_FILE}
            COMMAND echo "Point browser to ${CODE_COVERAGE_OUTPUT_DIR}/index.html to see coverage results"
    )
endif()

