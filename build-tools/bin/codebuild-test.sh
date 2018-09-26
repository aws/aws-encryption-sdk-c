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

build-tools/bin/codebuild-build-dependency https://github.com/awslabs/aws-c-common.git -DCMAKE_BUILD_TYPE=RelWithDebInfo
build-tools/bin/codebuild-build-dependency https://github.com/awslabs/aws-sdk-cpp.git --git-tag 1.6.18 -DBUILD_ONLY="kms;lambda" -DCMAKE_BUILD_TYPE=RelWithDebInfo
mkdir build
ls -l /deps/aws-c-common/install/lib/aws-c-common/cmake
# Run a lightweight test suite with valgrind...
(cd build;
    cmake -DREDUCE_TEST_ITERATIONS=TRUE -DVALGRIND_TEST_SUITE=ON -DFORCE_KMS_KEYRING_BUILD=ON -DAWS_ENC_SDK_END_TO_END_TESTS=ON -DCMAKE_PREFIX_PATH='/deps/aws-c-common/install;/deps/aws-sdk-cpp/install/lib/cmake' .. &&
    make VERBOSE=1 &&
    ctest --output-on-failure -j8)

# then run the full suite without valgrind
rm -rf build
mkdir build
ls -l /deps/aws-c-common/install/lib/aws-c-common/cmake
(cd build;
    cmake -DFORCE_KMS_KEYRING_BUILD=ON -DAWS_ENC_SDK_END_TO_END_TESTS=ON -DCMAKE_PREFIX_PATH='/deps/aws-c-common/install;/deps/aws-sdk-cpp/install/lib/cmake' .. &&
    make VERBOSE=1 &&
    ctest --output-on-failure -j8)


