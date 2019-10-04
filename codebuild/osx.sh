#!/bin/bash

# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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


set +ex

OS=$(uname -s)
CPP_VER="1.7.163"  #github versioned branch
BUILDROOT="/var/tmp/build-$(date +%s)"
OPENSSLVER="openssl@1.1" #note this is a brew label, not an exact version reference
BUILDROOT="/var/tmp/build-$(date +%Y%m%d)"
CSDK_VER="master"  # Build from master

deps(){
  if [ $(which brew|grep -c 'brew') -lt 1 ]; then
    echo "Can't find brew, required to build"
    exit 1
  fi
  brew install ${OPENSSLVER} cmake || true
  mkdir ${BUILDROOT} || true
  mkdir ${INSTALLROOT} || true
}

build_cpp(){
    echo "Building cpp"
    cd ${BUILDROOT}
    git clone -b ${CPP_VER} https://github.com/aws/aws-sdk-cpp.git
    mkdir -p ${BUILDROOT}/build-aws-sdk-cpp ||true
    mkdir -p ${BUILDROOT}/install || true 
    cd ${BUILDROOT}/build-aws-sdk-cpp
    # See https://docs.aws.amazon.com/sdk-for-cpp/v1/developer-guide/cmake-params.html#cmake-target-arch
    cmake -G Xcode -DTARGET_ARCH="APPLE" -DBUILD_SHARED_LIBS=ON -DBUILD_ONLY="kms" -DENABLE_UNITY_BUILD=ON ../aws-sdk-cpp 
    # This target runs the cpp tests, but doesn't appear to run the other dependancy tests.
    xcodebuild -target ALL_BUILD 
    xcodebuild -target install

}

build_csdk(){
    echo "Building csdk"
    cd ${BUILDROOT}
    git clone -b ${CSDK_VER} https://github.com/aws/aws-encryption-sdk-c.git 
    mkdir -p ${BUILDROOT}/build-csdk || true
    cd $BUILDROOT/build-csdk
    cmake -G Xcode -DBUILD_SHARED_LIBS=ON -DOPENSSL_ROOT_DIR="/usr/local/opt/${OPENSSLVER}" ../aws-encryption-sdk-c 
    xcodebuild -target ALL_BUILD
    xcodebuild -scheme RUN_TESTS

}


if [ "$OS" == 'Darwin' ]; then
    deps
    build_cpp
    build_csdk
else
	echo "Expecting Mac OS; exiting"
fi
