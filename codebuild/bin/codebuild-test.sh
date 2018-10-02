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

set -euxo pipefail

PATH=$PWD/build-tools/bin:$PATH
ROOT=$PWD

run_test() {
    rm -rf build
    mkdir build
    (cd build
    cmake -DFORCE_KMS_KEYRING_BUILD=ON -DAWS_ENC_SDK_END_TO_END_TESTS=ON \
        -DCMAKE_C_FLAGS="$CFLAGS" \
        -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
        -DCMAKE_SHARED_LINKER_FLAGS="$LDFLAGS" \
        -DOPENSSL_ROOT_DIR=/deps/openssl \
        -DVALGRIND_OPTIONS=--suppressions=$ROOT/valgrind.suppressions \
        -GNinja \
        .. "$@" 2>&1|head -n 1000)
    cmake --build $ROOT/build -- -v
    (cd build; ctest --output-on-failure -j8)
}

# Print env variables for debug purposes
env

# Run a lighter weight test suite under valgrind
run_test -DCMAKE_BUILD_TYPE=RelWithDebInfo -DREDUCE_TEST_ITERATIONS=TRUE -DVALGRIND_TEST_SUITE=ON -DCMAKE_PREFIX_PATH='/deps/install;/deps/static/install'
# Run the full test suite without valgrind, and as a shared library
run_test -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_SHARED_LIBS=ON -DCMAKE_PREFIX_PATH='/deps/install;/deps/shared/install'
# Also run the test suite as a debug build (probing for -DNDEBUG issues), and as a static library
run_test -DCMAKE_BUILD_TYPE=Debug -DCMAKE_PREFIX_PATH='/deps/install;/deps/shared/install'
