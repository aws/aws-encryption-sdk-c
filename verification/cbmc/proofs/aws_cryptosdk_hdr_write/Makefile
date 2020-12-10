# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

PROOF_UID = aws_cryptosdk_hdr_write

HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

# Values are chosen for performance. 
# Increaseing either does not increase the coverage. 
MAX_EDK_LIST_ITEMS ?= 1
MAX_IV_LEN ?= 12
MAX_TABLE_SIZE ?= 2

DEFINES += -DARRAY_LIST_TYPE="struct aws_cryptosdk_edk"
DEFINES += -DARRAY_LIST_TYPE_HEADER=\"aws/cryptosdk/edk.h\"
DEFINES += -DAWS_CRYPTOSDK_HASH_ELEMS_ARRAY_INIT_GENERATOR=array_list_item_generator
DEFINES += -DAWS_NO_STATIC_IMPL
DEFINES += -DMAX_EDK_LIST_ITEMS=$(MAX_EDK_LIST_ITEMS)
DEFINES += -DMAX_IV_LEN=$(MAX_IV_LEN)
DEFINES += -DMAX_TABLE_SIZE=$(MAX_TABLE_SIZE)

CBMCFLAGS +=

PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/byte_buf.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/hash_table.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/string.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/array_list.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/byte_order.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/error.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/math.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/string.c
PROJECT_SOURCES += $(SRCDIR)/source/cipher.c
PROJECT_SOURCES += $(SRCDIR)/source/edk.c
PROJECT_SOURCES += $(SRCDIR)/source/enc_ctx.c
PROJECT_SOURCES += $(SRCDIR)/source/header.c
PROJECT_SOURCES += $(SRCDIR)/source/utils.c

PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/proof_allocators.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/utils.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_array_list_defined_type.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_byte_buf_write_stub.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_hash_iter_overrides.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/error.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/memcmp_override.c
PROOF_SOURCES += $(PROOF_SOURCE)/cbmc_invariants.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(PROOF_STUB)/aws_array_list_sort_noop_stub.c
PROOF_SOURCES += $(PROOF_STUB)/aws_cryptosdk_enc_ctx_size_stub.c
PROOF_SOURCES += $(PROOF_STUB)/aws_cryptosdk_hash_elems_array_init_stub.c
PROOF_SOURCES += $(PROOF_STUB)/aws_default_allocator_stub.c
PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)

UNWINDSET += array_list_item_generator.0:$(call addone,$(MAX_TABLE_SIZE))
UNWINDSET += aws_cryptosdk_edk_list_elements_are_bounded.0:$(call addone,$(MAX_EDK_LIST_ITEMS))
UNWINDSET += aws_cryptosdk_edk_list_elements_are_valid.0:$(call addone,$(MAX_EDK_LIST_ITEMS))
UNWINDSET += aws_cryptosdk_enc_ctx_serialize.0:$(call addone,$(MAX_TABLE_SIZE))
UNWINDSET += aws_cryptosdk_hdr_write.0:$(call addone,$(MAX_EDK_LIST_ITEMS)) 
UNWINDSET += ensure_cryptosdk_edk_list_has_allocated_list_elements.0:$(call addone,$(MAX_EDK_LIST_ITEMS))

include ../Makefile.common
