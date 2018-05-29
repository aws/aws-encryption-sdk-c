#!/bin/bash

set -e # Fail if a subcommand fails
set -u # Fail if an unset variable is used
set -x # Echo commands as they're executed

PATH=$PWD/build-tools/bin:$PATH

build-tools/bin/codebuild-build-dependency https://github.com/awslabs/aws-c-common.git
build-tools/bin/codebuild-build-dependency https://github.com/awslabs/aws-sdk-cpp.git -DBUILD_ONLY="kms;lambda"
mkdir build
ls -l /deps/aws-c-common/install/lib/aws-c-common/cmake
(cd build;
    cmake -DCMAKE_PREFIX_PATH='/deps/aws-c-common/install;/deps/aws-sdk-cpp/install' .. &&
    make VERBOSE=1 &&
    (make test || (ctest -V; exit 1)))
