# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:latest

# Needed for setup-apt-cache.sh
ADD https://mirrors.kernel.org/ubuntu/pool/main/n/net-tools/net-tools_1.60+git20180626.aebd88e-1ubuntu1_amd64.deb /tmp
ADD https://mirrors.kernel.org/ubuntu/pool/universe/n/netcat/netcat-traditional_1.10-40_amd64.deb /tmp
RUN dpkg -i /tmp/net-tools_*.deb /tmp/netcat-*.deb

ADD bin/setup-apt-cache.sh /usr/local/bin/
ADD bin/setup-apt.sh /usr/local/bin/
RUN setup-apt-cache.sh
RUN setup-apt.sh

ENV PATH=/usr/local/bin:/usr/bin:/bin

ENV CC=/usr/bin/gcc
ENV CXX=/usr/bin/g++
ENV CFLAGS=
ENV CXXFLAGS=
ENV LDFLAGS=

# This docker image is similar to |ubuntu-latest-x64.Dockerfile| except OpenSSL is replaced with awslc.
# awslc is installed at /deps/install/lib.
ENV LDFLAGS="-Wl,-rpath -Wl,/deps/install/lib -Wl,-rpath -Wl,/deps/shared/install/lib -L/deps/install/lib -L/deps/shared/install/lib"

ADD bin/apt-install-pkgs /usr/local/bin/
ADD bin/install-shared-deps-awslc.sh /usr/local/bin/
RUN install-shared-deps-awslc.sh

ADD bin/install-aws-deps.sh /usr/local/bin
RUN install-aws-deps.sh

ADD bin/install-node.sh /usr/local/bin
RUN install-node.sh

ADD bin/codebuild-test.sh /usr/local/bin/

# Remove apt proxy configuration before publishing the dockerfile
RUN rm -f /etc/apt/apt.conf.d/99proxy
