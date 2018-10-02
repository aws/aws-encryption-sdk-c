#!/bin/bash

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

# This script builds and installs AWS-originated dependencies. Since we want to test
# building against both the static and shared variants, we build them twice, installing
# the results under /deps/static/install and /deps/shared/install

# This script uses the following environment variables:
# CC, CXX, CFLAGS, CXXFLAGS, LDFLAGS - Compiler and flags configuration

set -euxo pipefail

build_pkg() {
    INSTALLDIR=$1
    GITURL=$2
    GITREF=$3

    shift; shift; shift

    SRCDIR=/tmp/$(basename $GITURL .git)
    BUILDDIR=/tmp/build

    if ! [ -e $SRCDIR ]; then
        mkdir -p "$(dirname "$SRCDIR")"
        git clone --depth 1 --branch $GITREF "$GITURL" "$SRCDIR"
    fi

    mkdir $BUILDDIR
    (cd $BUILDDIR &&
     export LD_LIBRARY_PATH=/deps/install &&
     cmake $SRCDIR "$@" -DCMAKE_INSTALL_PREFIX=$root/install -DCMAKE_BUILD_TYPE=RelWithDebInfo -GNinja \
        -DCMAKE_PREFIX_PATH=/deps/install \
        -DCMAKE_C_FLAGS="$CFLAGS" \
        -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
        -DCMAKE_SHARED_LINKER_FLAGS="$LDFLAGS")
    cmake --build $BUILDDIR
    cmake --build $BUILDDIR --target install
    rm -rf $BUILDDIR
}

mkdir -p /deps

for libtype in shared static; do
    if [ $libtype == shared ]; then
        CMAKE_ARGS="-DBUILD_SHARED_LIBS=ON"
    else
        CMAKE_ARGS="-DBUILD_SHARED_LIBS=OFF"
    fi

    root=/deps/$libtype

    build_pkg $root/install https://github.com/awslabs/aws-c-common.git master $CMAKE_ARGS
    build_pkg $root/install https://github.com/awslabs/aws-sdk-cpp.git 1.6.18 $CMAKE_ARGS -DBUILD_ONLY=kms
done

