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

#########
# Local vars

# Use a smaller bound for buffer so the proof runs on a reasonable time
# Expected runtime is 2min for this bound
MAX_BUFFER_SIZE = 4

#########

PROOF_UID = aws_cryptosdk_decrypt_body
HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

CBMCFLAGS +=

DEFINES += -DMAX_BUFFER_SIZE=$(MAX_BUFFER_SIZE)

PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/allocator.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/byte_buf.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/common.c
PROJECT_SOURCES += $(PROOF_SOURCE)/openssl/err_override.c
PROJECT_SOURCES += $(PROOF_SOURCE)/openssl/evp_override.c
PROJECT_SOURCES += $(SRCDIR)/source/cipher.c

PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/utils.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/error.c
PROOF_SOURCES += $(COMMON_PROOF_UNINLINE)/error.c
PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_data_structures.c

REMOVE_FUNCTION_BODY += EVP_EncryptUpdate
REMOVE_FUNCTION_BODY += EVP_sha256
REMOVE_FUNCTION_BODY += EVP_sha384
REMOVE_FUNCTION_BODY += nondet_compare

UNWINDSET += aws_cryptosdk_decrypt_body.0:$(call addone,$(MAX_BUFFER_SIZE))
# This bound must be 37 because it process a string of fixed size in update_frame_aad
UNWINDSET += strlen.0:37
#########
include ../Makefile.common
