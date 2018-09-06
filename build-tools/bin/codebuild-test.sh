#!/bin/bash

# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use
# this file except in compliance with the License. A copy of the License is
# located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.

set -e # Fail if a subcommand fails
set -u # Fail if an unset variable is used
set -x # Echo commands as they're executed

PATH=$PWD/build-tools/bin:$PATH

build-tools/bin/codebuild-build-dependency https://github.com/awslabs/aws-c-common.git
build-tools/bin/codebuild-build-dependency https://github.com/awslabs/aws-sdk-cpp.git --git-tag 1.5.20 -DBUILD_ONLY="kms;lambda"
mkdir build
ls -l /deps/aws-c-common/install/lib/aws-c-common/cmake
(cd build;
    cmake -DVALGRIND_TEST_SUITE=ON -DCMAKE_PREFIX_PATH='/deps/aws-c-common/install;/deps/aws-sdk-cpp/install' .. &&
    make VERBOSE=1 &&
    ctest --output-on-failure -j8)
