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
MAX_TABLE_SIZE ?= 16
#A table has 10 words for the struct, plus 3 words for each entry
TABLE_SIZE_IN_WORDS=$(shell echo $$(($$((3 * $(MAX_TABLE_SIZE))) + 10)))

#########

PROOF_UID = aws_cryptosdk_enc_ctx_size

HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

CBMCFLAGS +=

# Use the generator from the harness
DEFINES += -DHASH_ITER_ELEMENT_GENERATOR=hash_iterator_generator2
DEFINES += -DMAX_TABLE_SIZE=$(MAX_TABLE_SIZE)

PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/common.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/hash_table.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/math.c
PROJECT_SOURCES += $(SRCDIR)/source/enc_ctx.c

PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/proof_allocators.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/utils.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_hash_iter_overrides.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/error.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/memset_override_0.c
PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)

REMOVE_FUNCTION_BODY += aws_hash_iter_begin
REMOVE_FUNCTION_BODY += aws_hash_iter_delete
REMOVE_FUNCTION_BODY += aws_hash_iter_done
REMOVE_FUNCTION_BODY += aws_hash_iter_next

UNWINDSET += aws_add_size_checked_varargs.0:5
UNWINDSET += aws_cryptosdk_enc_ctx_size.0:$(call addone,$(MAX_TABLE_SIZE))
UNWINDSET += memset_override_0_impl.0:$(call addone,$(TABLE_SIZE_IN_WORDS))
###########

include ../Makefile.common
