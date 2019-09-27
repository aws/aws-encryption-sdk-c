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

FROM ubuntu:14.04.5

COPY bin/* /usr/local/bin/

RUN /usr/local/bin/setup-apt-cache.sh
RUN /usr/local/bin/setup-apt-trusty.sh

ENV PATH=/usr/local/bin:/usr/bin:/bin

ENV CC=/usr/bin/gcc
ENV CXX=/usr/bin/g++
ENV CFLAGS=
ENV CXXFLAGS=
ENV LDFLAGS=

# We'll need a newer version of cmake than is available for this version of ubuntu.
# Because cmake depends on libssl, we'll want to build it either before we set -rpaths,
# or after we build libssl.
RUN /usr/local/bin/update-cmake.sh

# We're going to install our own version of openssl at /deps/install/lib - this lets us test against multiple openssl versions.
# However, this also means we need to install our own version of curl, as curl links against libssl and the C++ SDK links
# against curl. What's more, we can't remove system libcurl, as we'd need to build and install our own version of git if we
# did so. Sigh.
#
# To deal with this mess, set up a bunch of -rpath overrides to ensure that all the binaries we build look in a different
# library directory first. We do this setup after configuring cmake, as we don't particularly need/want cmake to depend
# on our special versions of openssl/libcurl (or to depend on them at all for that matter).
ENV LDFLAGS="-Wl,-rpath -Wl,/deps/install/lib -Wl,-rpath -Wl,/deps/shared/install/lib -L/deps/install/lib -L/deps/shared/install/lib"

ENV OPENSSL_TAG=OpenSSL_1_0_2h
ENV OPENSSL_PLATFORM=linux-x86_64
RUN /usr/local/bin/install-shared-deps.sh && install-aws-deps.sh
# Remove apt proxy configuration before publishing the dockerfile
RUN rm -f /etc/apt/apt.conf.d/99proxy
