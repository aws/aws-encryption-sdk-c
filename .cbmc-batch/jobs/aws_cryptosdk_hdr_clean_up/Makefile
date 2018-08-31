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

goto: proofs.goto
	goto-instrument proofs.goto proofs.goto

proofs.goto: aws-c-common config
	cd ../../..; \
    goto-cc .cbmc-batch/header_proofs.c source/header.c aws-c-common/source/byte_buf.c \
    aws-c-common/source/common.c aws-c-common/source/error.c \
    -Iinclude -Iaws-c-common/include -I.cbmc -o .cbmc-batch/jobs/aws_cryptosdk_hdr_clean_up/proofs.goto \
    --function aws_cryptosdk_hdr_clean_up_verify

config:
	cd ../../../; \
    cp .cbmc-batch/config.h include/aws/cryptosdk/private/config.h

aws-c-common:
	cd ../../..; \
    git clone https://github.com/awslabs/aws-c-common.git

clean:
	rm proofs.goto; \
    rm -rf ../../../aws-c-common
