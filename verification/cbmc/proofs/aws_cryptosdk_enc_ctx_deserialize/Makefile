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

#Expected runtime on my laptop: 5m30s
#########
# Local vars
MAX_NUM_ELEMS = 2

#########

PROOF_UID = aws_cryptosdk_enc_ctx_deserialize

HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

CBMCFLAGS +=

DEFINES += -DAWS_BYTE_CURSOR_READ_BE16_GENERATOR=aws_byte_cursor_read_be16_generator_for_enc_ctx_deserialize
DEFINES += -DMAX_NUM_ELEMS=$(MAX_NUM_ELEMS)

PROOF_SOURCES += $(CBMC_ROOT)/aws-c-common/source/allocator.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/utils.c
#if we don't include the hash_table.c, we don't need to remove their function bodies
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_byte_cursor_read_be16_override.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_hash_table_no_slots_override.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_string_destroy_override.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_string_new_from_array_override.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/error.c
PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)

PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/byte_buf.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/common.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/hash_table.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/math.c
PROJECT_SOURCES += $(SRCDIR)/source/enc_ctx.c

REMOVE_FUNCTION_BODY += aws_byte_cursor_read_be16
REMOVE_FUNCTION_BODY += aws_string_destroy
REMOVE_FUNCTION_BODY += aws_string_new_from_array

UNWINDSET += aws_cryptosdk_enc_ctx_deserialize.0:$(call addone,$(MAX_NUM_ELEMS))
###########
include ../Makefile.common
