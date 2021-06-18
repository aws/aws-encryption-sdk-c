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
NUM_CPU_THREADS=$(grep -c ^processor /proc/cpuinfo)

# End to end tests require valid credentials (instance role, etc..)
# Disable for local runs.
if [ -f "/sys/hypervisor/uuid" ]; then
        ONEC2=$(grep -c ec2 /sys/hypervisor/uuid)
        if [ "${ONEC2}" -gt 0 ]; then
            E2E="ON";
        else
            E2E="OFF";
        fi
elif [ -n "$CODEBUILD_BUILD_ARN" ]; then
    E2E="ON";
else
    E2E="OFF";
fi

debug() {
# If the threading test does in fact fail, it does so by crashing.
# Since this sort of bug might not be reproducible, make sure to dump
# some useful information before failing.
    ulimit -c unlimited
    if ! "$@"; then
        if [ -e core.* ]; then
            gdb -x "$ROOT/codebuild/gdb.commands" "$1" core.* 
            exit 1
        fi
    fi
}

run_test() {
    PREFIX_PATH="$1"
    shift

    rm -rf build
    mkdir build
    (cd build
    #TODO: EC2 metadata service fails; fix an re-enable end2end tests.
    cmake -DBUILD_AWS_ENC_SDK_CPP=ON -DAWS_ENC_SDK_END_TO_END_TESTS=${E2E} \
        -DAWS_ENC_SDK_KNOWN_GOOD_TESTS=ON \
        -DAWS_ENC_SDK_END_TO_END_EXAMPLES=${E2E} \
        -DCMAKE_C_FLAGS="$CFLAGS" \
        -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
        -DCMAKE_SHARED_LINKER_FLAGS="$LDFLAGS" \
        -DOPENSSL_ROOT_DIR=/deps/openssl \
        -DVALGRIND_OPTIONS="--gen-suppressions=all;--suppressions=$ROOT/valgrind.suppressions" \
        -DCMAKE_PREFIX_PATH="$PREFIX_PATH" \
        -DBUILD_SHARED_LIBS="$BUILD_SHARED_LIBS" \
        -GNinja \
        .. "$@" 2>&1|head -n 1000)
    cmake --build $ROOT/build -- -v
    (cd build; ctest --output-on-failure -j${NUM_CPU_THREADS})
    (cd build; debug ./tests/test_local_cache_threading) || exit 1
    "$ROOT/codebuild/bin/test-install.sh" "$PREFIX_PATH" "$PWD/build"
}

# Print env variables for debug purposes
env

case "$TEST_MODE" in
    dynamic)
        # Run the full test suite without valgrind, and as a shared library
        export BUILD_SHARED_LIBS=on
        run_test '/deps/install;/deps/shared/install' -DCMAKE_BUILD_TYPE=RelWithDebInfo
        ;;
    static_debug)
        # Also run the test suite as a debug build (probing for -DNDEBUG issues), and as a static library
        export BUILD_SHARED_LIBS=off
        run_test '/deps/install;/deps/static/install' -DCMAKE_BUILD_TYPE=Debug
        ;;
    static_valgrind)
        # Run a lighter weight test suite under valgrind
        export BUILD_SHARED_LIBS=off
        run_test '/deps/install;/deps/static/install' \
            -DCMAKE_BUILD_TYPE=RelWithDebInfo -DREDUCE_TEST_ITERATIONS=TRUE -DVALGRIND_TEST_SUITE=ON
        ;;
    *)
        echo "unknown TEST_MODE: $TEST_MODE"
        exit 1
        ;;
esac
