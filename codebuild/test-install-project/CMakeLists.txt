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

cmake_minimum_required (VERSION 3.1)
project (test)

set(PROJECT_NAME test-app)

find_package(aws-encryption-sdk CONFIG REQUIRED)

add_executable(testapp "test.c")
target_link_libraries(testapp PUBLIC AWS::aws-encryption-sdk)
set_target_properties(testapp PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
