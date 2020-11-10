# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

# if Makefile.local exists, use it. This provides a way to override the defaults
sinclude ../Makefile.local
#otherwise, use the default values
include ../Makefile.local_default
include ../Makefile.aws_byte_buf

# Use a smaller bound for buffer so the proof runs on a reasonable time
# Expected runtime is 2min for this bound
MAX_BUFFER_SIZE = 4

UNWINDSET += aws_cryptosdk_encrypt_body.0:$(call addone,$(MAX_BUFFER_SIZE))
# This bound must be 37 because it process a string of fixed size in update_frame_aad
UNWINDSET += strlen.0:37

CBMCFLAGS +=

HARNESS_ENTRY = aws_cryptosdk_encrypt_body_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(HARNESS_FILE)

PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/proof_allocators.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/utils.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/byte_buf.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/common.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/error.c
PROJECT_SOURCES += $(SRCDIR)/source/cipher.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_data_structures.c
PROJECT_SOURCES += $(PROOF_SOURCE)/openssl/evp_override.c

REMOVE_FUNCTION_BODY += aws_raise_error_private
REMOVE_FUNCTION_BODY += EVP_DecryptUpdate
REMOVE_FUNCTION_BODY += EVP_sha256
REMOVE_FUNCTION_BODY += EVP_sha384
REMOVE_FUNCTION_BODY += nondet_compare

include ../Makefile.common
