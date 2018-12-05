
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

find_package(aws-c-common CONFIG REQUIRED)
find_package(aws-encryption-sdk CONFIG REQUIRED)
find_package(AWSSDK CONFIG REQUIRED COMPONENTS core kms)
include(${CMAKE_CURRENT_LIST_DIR}/@AWS_INSTALL_TARGET@-targets.cmake)
