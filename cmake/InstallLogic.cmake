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

include(CMakeParseArguments)

function(aws_install_target)
    set(oneValueArgs TARGET)
    set(multiValueArgs HEADERS HEADER_ROOTS)
    CMAKE_PARSE_ARGUMENTS(AWS_INSTALL "" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    foreach(HEADER_SRCPATH IN ITEMS ${AWS_INSTALL_HEADERS})
        get_filename_component(HEADER_DIR ${HEADER_SRCPATH} DIRECTORY)
        set(foundPrefix FALSE)
        set(headerSuffix "")

        foreach(HEADER_ROOT IN ITEMS ${AWS_INSTALL_HEADER_ROOTS})
            string(LENGTH "${HEADER_ROOT}" prefixLength)
            string(FIND "${HEADER_DIR}" "${HEADER_ROOT}" substringOffset)

            if(${substringOffset} EQUAL 0)
                string(SUBSTRING "${HEADER_DIR}" ${prefixLength} -1 headerSuffix)
                set(foundPrefix TRUE)
                break()
            endif()
        endforeach(HEADER_ROOT)

        if(NOT ${foundPrefix})
            message(SEND_ERROR "Couldn't determine header root for ${HEADER_SRCPATH}")
        else()
            install(FILES ${HEADER_SRCPATH} DESTINATION ${CMAKE_INSTALL_PREFIX}/include/${headerSuffix})
        endif()
    endforeach(HEADER_SRCPATH)

    install(TARGETS ${AWS_INSTALL_TARGET} EXPORT ${AWS_INSTALL_TARGET}-targets
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")

    configure_file("${PROJECT_SOURCE_DIR}/cmake/${AWS_INSTALL_TARGET}-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/${AWS_INSTALL_TARGET}-config.cmake" @ONLY)
    install(EXPORT "${AWS_INSTALL_TARGET}-targets" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${AWS_INSTALL_TARGET}/cmake/"
        NAMESPACE AWS::
    )

    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${AWS_INSTALL_TARGET}-config.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${AWS_INSTALL_TARGET}/cmake/")
endfunction(aws_install_target)
