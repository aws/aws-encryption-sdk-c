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

PROOF_UID = aws_cryptosdk_hdr_size

HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

# Increasing the length of the edk_list or enc_ctx beyond 2 does not improve coverage.
# There we set both to 2 for performance.
MAX_EDK_LIST_ITEMS ?= 2
MAX_TABLE_SIZE ?= 2

DEFINES += -DAWS_NO_STATIC_IMPL
DEFINES += -DMAX_EDK_LIST_ITEMS=$(MAX_EDK_LIST_ITEMS)
DEFINES += -DMAX_TABLE_SIZE=$(MAX_TABLE_SIZE)
DEFINES += -DARRAY_LIST_TYPE="struct aws_cryptosdk_edk"
DEFINES += -DARRAY_LIST_TYPE_HEADER=\"aws/cryptosdk/edk.h\"

CBMCFLAGS +=

PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/byte_buf.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/hash_table.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/array_list.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/byte_order.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/error.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/math.c
PROJECT_SOURCES += $(SRCDIR)/source/cipher.c
PROJECT_SOURCES += $(SRCDIR)/source/edk.c
PROJECT_SOURCES += $(SRCDIR)/source/enc_ctx.c
PROJECT_SOURCES += $(SRCDIR)/source/header.c
PROJECT_SOURCES += $(SRCDIR)/source/utils.c

PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/proof_allocators.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/utils.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_array_list_defined_type.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/error.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/memcmp_override.c
PROOF_SOURCES += $(PROOF_SOURCE)/cbmc_invariants.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(PROOF_STUB)/aws_cryptosdk_enc_ctx_size_stub.c
PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)

REMOVE_FUNCTION_BODY += aws_cryptosdk_enc_ctx_size
REMOVE_FUNCTION_BODY += aws_array_list_get_at_ptr

UNWINDSET += aws_cryptosdk_edk_list_elements_are_bounded.0:$(call addone,$(MAX_EDK_LIST_ITEMS))
UNWINDSET += aws_cryptosdk_edk_list_elements_are_valid.0:$(call addone,$(MAX_EDK_LIST_ITEMS))
UNWINDSET += aws_cryptosdk_hdr_size.0:$(call addone,$(MAX_EDK_LIST_ITEMS)) 
UNWINDSET += ensure_cryptosdk_edk_list_has_allocated_list_elements.0:$(call addone,$(MAX_EDK_LIST_ITEMS))
UNWINDSET += memcmp.0:$(call addone,$(MAX_BUFFER_SIZE))

include ../Makefile.common
