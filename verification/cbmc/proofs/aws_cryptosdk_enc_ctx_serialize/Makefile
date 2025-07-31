# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#########
# Local vars
#expected runtime: 2m45s
MAX_TABLE_SIZE ?= 2

#A table has 10 words for the struct, plus 3 words for each entry
TABLE_SIZE_IN_WORDS=$(shell echo $$(($$((3 * $(MAX_TABLE_SIZE))) + 10)))

#########
# Vars for Makefile.common

# Disable pointer overflow check
CBMC_FLAG_POINTER_OVERFLOW_CHECK=

PROOF_UID = aws_cryptosdk_enc_ctx_serialize

HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

CBMCFLAGS +=

DEFINES += -DAWS_CRYPTOSDK_HASH_ELEMS_ARRAY_INIT_GENERATOR=array_list_item_generator
DEFINES += -DAWS_NO_STATIC_IMPL
DEFINES += -DMAX_TABLE_SIZE=$(MAX_TABLE_SIZE)
DEFINES += -DMEMCPY_STUB_MAX=128

PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/byte_buf.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/common.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/hash_table.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/math.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/string.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/array_list.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/byte_order.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/error.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/math.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/string.c
PROJECT_SOURCES += $(SRCDIR)/source/enc_ctx.c

PROOF_SOURCES += $(CBMC_ROOT)/aws-c-common/source/allocator.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/utils.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/error.c
PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_STUB)/aws_array_list_sort_noop_stub.c
PROOF_SOURCES += $(PROOF_STUB)/aws_cryptosdk_enc_ctx_size_stub.c
PROOF_SOURCES += $(PROOF_STUB)/aws_cryptosdk_hash_elems_array_init_stub.c

#Remove function bodies to deal with CBMC function pointer removal
REMOVE_FUNCTION_BODY += aws_array_list_sort
REMOVE_FUNCTION_BODY += aws_byte_buf_write
REMOVE_FUNCTION_BODY += aws_cryptosdk_enc_ctx_size
REMOVE_FUNCTION_BODY += aws_cryptosdk_hash_elems_array_init

UNWINDSET += array_list_item_generator.0:$(call addone,$(MAX_TABLE_SIZE))
UNWINDSET += aws_cryptosdk_enc_ctx_serialize.0:$(call addone,$(MAX_TABLE_SIZE))
###########

include ../Makefile.common
