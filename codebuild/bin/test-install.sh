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

MY_PATH="$(dirname "$0")"
CODEBUILD_BASE="$MY_PATH/.."

PREFIX_PATH="$1"
BUILD_DIR="$2"
BUILD_SHARED_LIBS=${BUILD_SHARED_LIBS:-off}

rm -rf /tmp/TEST_INSTALL
cmake -DCMAKE_INSTALL_PREFIX=/tmp/TEST_INSTALL -DBUILD_SHARED_LIBS="$BUILD_SHARED_LIBS" "$BUILD_DIR"
cmake --build "$BUILD_DIR" --target install

for i in test-install-project test-install-project-cpp; do
    PROJECT="$CODEBUILD_BASE/$i"
    PROJECT_BUILD="$PROJECT/build"

    rm -rf "$PROJECT_BUILD"
    mkdir "$PROJECT_BUILD"
    (cd "$PROJECT_BUILD"; cmake .. -DBUILD_SHARED_LIBS="$BUILD_SHARED_LIBS" -DCMAKE_PREFIX_PATH="$1;/tmp/TEST_INSTALL")
    cmake --build "$PROJECT_BUILD"
    "$PROJECT_BUILD/testapp"
done
