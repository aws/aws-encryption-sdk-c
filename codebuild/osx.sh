#!/bin/bash
# OSX build script placeholder.

set -ex

OS=$(uname -s)
CPP_VER="1.7.163"  #github versioned branch
BUILDROOT="/var/tmp/build-$(date +%s)"
BUILDLOG="${BUILDROOT}/build.log"
#OPENSSLVER="openssl@1.1" #note this is a brew label, not an exact version reference
OPENSSLVER="openssl"
#BUILDROOT="/var/tmp/build-$(date +%s)"
BUILDROOT="/var/tmp/build-1569628622"
CSDK_VER="master" 

deps(){
  if [ $(which brew|grep -c 'brew') -lt 1 ]; then
    echo "Can't find brew, required to build"
    exit 1
  fi
  #brew install openssl@1.1 cmake || true
  mkdir $BUILDROOT || true
  mkdir $INSTALLROOT || true
}

build_cpp(){
    echo "Building cpp"
    cd $BUILDROOT
    git clone -b $CPP_VER https://github.com/aws/aws-sdk-cpp.git
    mkdir -p $BUILDROOT/build-aws-sdk-cpp ||true
    mkdir -p $BUILDROOT/install || true 
    cd $BUILDROOT/build-aws-sdk-cpp
    cmake -DBUILD_SHARED_LIBS=ON -DBUILD_ONLY="kms" -DENABLE_UNITY_BUILD=ON ../aws-sdk-cpp | tee -a ${BUILDLOG}
    make | tee -a ${BUILDLOG}
    make install | tee -a ${BUILDLOG}
}

build_csdk(){
    echo "Building csdk"
    cd $BUILDROOT
    git clone -b ${CSDK_VER} https://github.com/aws/aws-encryption-sdk-c.git | tee -a ${BUILDLOG}
    mkdir -p $BUILDROOT/build-csdk || true
    cd $BUILDROOT/build-csdk
    cmake  -DBUILD_SHARED_LIBS=ON -DBUILD_DOC="ON" -DOPENSSL_ROOT_DIR="/usr/local/opt/${OPENSSLVER}" ../aws-encryption-sdk-c |tee -a ${BUILDLOG}
#    make |tee -a ${BUILDLOG}
#    make install |tee -a ${BUILDLOG}
#    make test '\-\-verbose' |tee -a ${BUILDLOG}

}

clean(){
for i in /usr/local/include/aws/cryptosdk/cache.h \
    /usr/local/include/aws/cryptosdk/cipher.h \
    /usr/local/include/aws/cryptosdk/default_cmm.h \
    /usr/local/include/aws/cryptosdk/edk.h \
    /usr/local/include/aws/cryptosdk/enc_ctx.h \
    /usr/local/include/aws/cryptosdk/error.h \
    /usr/local/include/aws/cryptosdk/exports.h \
    /usr/local/include/aws/cryptosdk/header.h \
    /usr/local/include/aws/cryptosdk/keyring_trace.h \
    /usr/local/include/aws/cryptosdk/list_utils.h \
    /usr/local/include/aws/cryptosdk/materials.h \
    /usr/local/include/aws/cryptosdk/multi_keyring.h \
    /usr/local/include/aws/cryptosdk/raw_aes_keyring.h \
    /usr/local/include/aws/cryptosdk/raw_rsa_keyring.h \
    /usr/local/include/aws/cryptosdk/session.h \
    /usr/local/include/aws/cryptosdk/vtable.h \
    /usr/local/include/aws/cryptosdk/version.h \
    /usr/local/lib/libaws-encryption-sdk.dylib \
    /usr/local/lib/aws-encryption-sdk/cmake/aws-encryption-sdk-targets.cmake \
    /usr/local/lib/aws-encryption-sdk/cmake/aws-encryption-sdk-targets-noconfig.cmake \
    /usr/local/lib/aws-encryption-sdk/cmake/aws-encryption-sdk-config.cmake \
    /usr/local/include/aws/cryptosdk/cpp/exports.h \
    /usr/local/include/aws/cryptosdk/cpp/kms_keyring.h \
    /usr/local/lib/libaws-encryption-sdk-cpp.dylib \
    /usr/local/lib/aws-encryption-sdk-cpp/cmake/aws-encryption-sdk-cpp-targets.cmake \
    /usr/local/lib/aws-encryption-sdk-cpp/cmake/aws-encryption-sdk-cpp-targets-noconfig.cmake \
    /usr/local/lib/aws-encryption-sdk-cpp/cmake/aws-encryption-sdk-cpp-config.cmake; do
    rm -f ${i};
done
}

if [ "$OS" == 'Darwin' ]; then
  if [ "$#" -eq 0 ]; then
   # deps
   # build_cpp
    build_csdk
  else
    case $1 in
      "clean") 
        clean;;
      *)
        echo "What now?  look at the script to find the exact func to call..."
      ;;
    esac
   fi
fi
