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

# This script builds and uploads all linux docker images.
# The ECS_REGISTRY environment variable can be used to override which registry to upload to.

set -euxo pipefail

ECS_SERVER="636124823696.dkr.ecr.us-west-2.amazonaws.com"
ECS_REGISTRY=${ECS_REGISTRY:-${ECS_SERVER}/linux-docker-images}
_AUTH_TOKEN=`aws ecr get-login-password --region us-west-2`
docker login --password ${_AUTH_TOKEN}  --username AWS ${ECS_SERVER}

build_image() {
    docker build -t $1 -f $1.Dockerfile .
    docker tag $1:latest $ECS_REGISTRY:$1
    docker push $ECS_REGISTRY:$1
}

build_image ubuntu-latest-x64
build_image ubuntu-latest-x64-awslc
