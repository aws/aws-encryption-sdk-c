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

./aws-encryption-sdk-specification/util/test_conditions \
    -s '-r include/ --include *.h' \
    -s 'source/*.c' \
    -t '-r tests/ --include *.[ch]' \
    -s '-r aws-encryption-sdk-cpp/include/ --include *.h' \
    -s '-r aws-encryption-sdk-cpp/source/ --include *.cpp' \
    -t '-r aws-encryption-sdk-cpp/tests/ --include *.h' \
    -t '-r aws-encryption-sdk-cpp/tests/ --include *.cpp' \
    -s 'compliance/*.txt'
