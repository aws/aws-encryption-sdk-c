#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# This script is similar to |install-shared-deps.sh| except below differences:
# 1. OpenSSL is replaced with awslc.
# 2. LibCurl version is updated to 7.74.
# After this script, awslc(static and shared) and curl will be installed under /deps/install.

set -euxo pipefail

export AWSLC_SRC_DIR=/tmp/awslc
export INSTALL_DIR=/deps/install
export LD_LIBRARY_PATH=${INSTALL_DIR}
export NUM_CPU_THREADS=$(nproc)

function download_awslc() {
    AWSLC_GIT_URL='https://github.com/awslabs/aws-lc.git'
    AWSLC_GIT_REF='main'
    rm -rf ${AWSLC_SRC_DIR}
    mkdir -p ${AWSLC_SRC_DIR}
    git clone --depth 1 --branch ${AWSLC_GIT_REF} --recurse-submodules "${AWSLC_GIT_URL}" "${AWSLC_SRC_DIR}"
}

function build_awslc() {
    BUILD_DIR=/tmp/build/awslc
    rm -rf ${BUILD_DIR}
    mkdir -p ${BUILD_DIR}
    CMAKE_BUILD_COMMAND="cmake ${AWSLC_SRC_DIR} $@ \
        -GNinja \
        -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR} \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo"
    if [[ !(-z "${CFLAGS+x}" || -z "${CFLAGS}") ]]; then
        CMAKE_BUILD_COMMAND="${CMAKE_BUILD_COMMAND} -DCMAKE_C_FLAGS=${CFLAGS}"
    fi
    if [[ !(-z "${CXXFLAGS+x}" || -z "${CXXFLAGS}") ]]; then
        CMAKE_BUILD_COMMAND="${CMAKE_BUILD_COMMAND} -DCMAKE_CXX_FLAGS=${CXXFLAGS}"
    fi
    (cd ${BUILD_DIR} && ${CMAKE_BUILD_COMMAND})
    cmake --build ${BUILD_DIR}
    cmake --build ${BUILD_DIR} --target install
    rm -rf ${BUILD_DIR}
}

function install_libcurl() {
    mkdir /deps/curl
    cd /deps/curl
    wget https://curl.haxx.se/download/curl-7.74.0.tar.gz
    tar xzf curl-*.tar.gz
    cd curl-*/
    # awslc is forked from boringssl.
    # |OPENSSL_IS_AWSLC| macro is equivalent to |OPENSSL_IS_BORINGSSL|.
    # Replacing OPENSSL_IS_BORINGSSL with OPENSSL_IS_AWSLC.
    find ./ -type f -exec sed -i -e 's/OPENSSL_IS_BORINGSSL/OPENSSL_IS_AWSLC/g' {} \;
    ./configure --with-ssl=/deps/install \
        --prefix=/deps/install \
        --disable-ldap \
        --without-libidn \
        --without-gnutls \
        --without-nss \
        --without-gssapi
    make -j"${NUM_CPU_THREADS}"
    make install
    cd /
    rm -rf /deps/curl
}

mkdir -p /deps

download_awslc

build_awslc '-DBUILD_SHARED_LIBS=ON'
build_awslc '-DBUILD_SHARED_LIBS=OFF'

install_libcurl
