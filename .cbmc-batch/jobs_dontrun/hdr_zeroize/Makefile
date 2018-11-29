# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

include ../Makefile

goto: proofs.goto
	goto-instrument proofs.goto proofs.goto

proofs.goto: aws-c-common config
	cd ../../..; \
	goto-cc .cbmc-batch/hdr_zeroize.c aws-c-common/source/byte_buf.c \
    aws-c-common/source/common.c aws-c-common/source/error.c \
    -Iinclude -Iaws-c-common/include -o .cbmc-batch/jobs/hdr_zeroize/proofs.goto \
    --function hdr_zeroize_verify
