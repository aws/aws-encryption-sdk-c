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

# This script installs non-AWS dependencies. Currently this is openssl, libcurl and json-c.

# We install openssl primarily to control the version being used, but also to turn on
# -DPURIFY to silence some valgrind warnings.

# We install libcurl because we need a version that links against the version of openssl
# in use, to avoid version conflicts.

# We install json-c because we require it to manipulate json objects while running checks  
# on known good test vectors.

# env variables used:
# $OPENSSL_PLATFORM: The openssl platform name (e.g. linux-generic32)
# CC, CXX, CFLAGS, CXXFLAGS, LDFLAGS: The usual compiler flags (as used by the respective package
#                                     configure scripts)
# OPENSSL_TAG: The tag or branch of openssl to build


set -euxo pipefail

mkdir -p /deps

git clone --depth 1 --branch $OPENSSL_TAG https://github.com/openssl/openssl.git /deps/openssl_src
cd /deps/openssl_src
# -DPURIFY tries to avoid confusing valgrind (e.g. avoiding using uninitialized memory as entropy)
./Configure --prefix=/deps/install shared -DPURIFY $OPENSSL_PLATFORM
make depend
make -j8
make install
cd /
rm -rf /deps/openssl_src

# We need a libcurl compatible with our version of openssl as well
mkdir /deps/curl
cd /deps/curl
wget https://curl.haxx.se/download/curl-7.61.1.tar.gz
tar xzf curl-*.tar.gz
cd curl-*/
./configure --with-ssl=/deps/install --prefix=/deps/install \
    --without-gnutls --without-nss --without-gssapi
make -j8
make install
cd /
rm -rf /deps/curl

mkdir /deps/json-c
cd /deps/json-c
wget https://s3.amazonaws.com/json-c_releases/releases/json-c-0.13.tar.gz
tar xzf json-c-*.tar.gz
cd json-c-*/
./configure --prefix=/deps/install
make -j8
make install
cd /
rm -rf /deps/json-c
