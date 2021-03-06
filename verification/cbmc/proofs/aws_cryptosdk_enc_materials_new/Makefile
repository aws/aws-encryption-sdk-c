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

include ../Makefile.string

# Expected runtime 38sec

PROOF_UID = aws_cryptosdk_enc_materials_new

HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

CBMCFLAGS +=

DEFINES += -DAWS_DEEP_CHECKS=1
DEFINES += -DKEYRING_TRACE_SIZE=10 # Value is hardcoded in aws_cryptosdk_keyring_trace_init

PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/byte_buf.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/common.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/math.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/atomics.c
PROJECT_SOURCES += $(PROOF_SOURCE)/openssl/bn_override.c
PROJECT_SOURCES += $(PROOF_SOURCE)/openssl/ec_override.c
PROJECT_SOURCES += $(PROOF_SOURCE)/openssl/evp_override.c
PROJECT_SOURCES += $(SRCDIR)/source/cipher.c
PROJECT_SOURCES += $(SRCDIR)/source/cipher_openssl.c
PROJECT_SOURCES += $(SRCDIR)/source/edk.c
PROJECT_SOURCES += $(SRCDIR)/source/keyring_trace.c
PROJECT_SOURCES += $(SRCDIR)/source/materials.c

PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/proof_allocators.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/utils.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_hash_table_no_slots_override.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/error.c
PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_data_structures.c

REMOVE_FUNCTION_BODY += aws_array_list_get_at_ptr
REMOVE_FUNCTION_BODY += aws_cryptosdk_edk_clean_up
REMOVE_FUNCTION_BODY += aws_cryptosdk_edk_is_valid
REMOVE_FUNCTION_BODY += aws_cryptosdk_keyring_trace_record_is_valid
REMOVE_FUNCTION_BODY += aws_cryptosdk_sig_ctx_is_valid

UNWINDSET += aws_cryptosdk_keyring_trace_is_valid.0:$(call addone,$(KEYRING_TRACE_SIZE))

include ../Makefile.common
