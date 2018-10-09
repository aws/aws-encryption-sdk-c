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

set -euxo pipefail

mkdir -p /deps

# Ubuntu 14.04's version of cmake3 is too old for the AWS SDK for C++
# (it fails when we try to use it from the encryption SDK's build scripts).
# We'll use the distro version to bootstrap and build a newer version.

# Note that we could skip the distro version and use the ./bootstrap script
# in the cmake distribution ... but this takes way longer, as it'll end up
# compiling a bootstrap cmake single-threaded, then recompile cmake again
# after configuring itself.
mkdir -p /deps/cmake
(cd /deps/cmake;
 wget https://cmake.org/files/v3.12/cmake-3.12.2.tar.gz;
 tar xzvf cmake-*.tar.gz;
 cd cmake-*;
 mkdir build;
 cd build;
 cmake .. -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local;
 ninja;
 ninja install)
rm -rf /deps/cmake

