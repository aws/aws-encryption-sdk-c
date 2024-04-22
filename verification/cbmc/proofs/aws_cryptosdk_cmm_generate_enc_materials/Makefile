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

#########
# if Makefile.local exists, use it. This provides a way to override the defaults
sinclude ../Makefile.local
#otherwise, use the default values
include ../Makefile.local_default

include ../Makefile.string

#########
# Local vars

# gets full coverage, runtime 3 min.
MAX_NUM_ITEMS ?= 1
DEFINES += -DMAX_NUM_ITEMS=$(MAX_NUM_ITEMS)

#########

PROOF_UID = aws_cryptosdk_cmm_generate_enc_materials
HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

CBMCFLAGS +=

# Enable after https://github.com/diffblue/cbmc/issues/5344 is fixed
#DEFINES += -DAWS_DEEP_CHECKS=1

PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/byte_buf.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/common.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/hash_table.c
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

PROOF_SOURCES += $(CBMC_ROOT)/aws-c-common/source/allocator.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/utils.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_hash_table_no_slots_override.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_string_destroy_override.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/error.c
PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/cbmc_invariants.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_data_structures.c

UNWINDSET += aws_cryptosdk_edk_list_clear.0:$(call addone,$(MAX_NUM_ITEMS))
UNWINDSET += aws_cryptosdk_edk_list_elements_are_bounded.0:$(call addone,$(MAX_NUM_ITEMS))
UNWINDSET += aws_cryptosdk_edk_list_elements_are_valid.0:$(call addone,$(MAX_NUM_ITEMS))
UNWINDSET += aws_cryptosdk_edk_list_is_bounded.0:$(call addone,$(MAX_NUM_ITEMS))
UNWINDSET += aws_cryptosdk_edk_list_is_valid.0:$(call addone,$(MAX_NUM_ITEMS))
UNWINDSET += aws_cryptosdk_keyring_trace_clear.0:$(call addone,$(MAX_NUM_ITEMS))
UNWINDSET += aws_cryptosdk_keyring_trace_is_valid.0:$(call addone,$(MAX_NUM_ITEMS))
UNWINDSET += ensure_cryptosdk_edk_list_has_allocated_list_elements.0:$(call addone,$(MAX_NUM_ITEMS))
UNWINDSET += ensure_cryptosdk_edk_list_has_allocated_members.0:$(call addone,$(MAX_NUM_ITEMS))
UNWINDSET += ensure_trace_has_allocated_records.0:$(call addone,$(MAX_NUM_ITEMS))
###########
include ../Makefile.common
