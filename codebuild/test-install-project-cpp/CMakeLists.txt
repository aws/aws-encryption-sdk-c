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

find_package(aws-encryption-sdk-cpp CONFIG REQUIRED)



add_executable(testapp "test.cpp")
target_link_libraries(testapp PUBLIC AWS::aws-encryption-sdk-cpp)
set_property(TARGET testapp PROPERTY CXX_STANDARD 11)
set_property(TARGET testapp PROPERTY LINKER_LANGUAGE CXX)

