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

# When doing rapid iteration on dockerfiles, the apt package download step can take
# significant time. This script attempts to use an apt-cacher-ng proxy on the host
# to reduce this time. If such a proxy is not running, we'll fall back to directly
# connecting to the distribution's apt repository.

set -euxo pipefail

# Find the host's IP
HOST_IP=`route -n | grep '^0.0.0.0' | perl -pe 's/^\S+\s+(\S+)\s.*/$1/'`

# Is a proxy running?
if nc -e /bin/true $HOST_IP 3142 < /dev/null; then
    echo "=== Enabling apt proxy on http://$HOST_IP:3142"
    echo "Acquire::http { Proxy \"http://$HOST_IP:3142\"; };" > /etc/apt/apt.conf.d/99proxy
fi
