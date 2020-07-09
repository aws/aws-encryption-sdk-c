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

#########
# Local vars
MAX_NUM_ELEMS = 4
# Time on my laptop: 4m50s
#########
#if we don't include the hash_table.c, we don't need to remove their function bodies
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_hash_table_no_slots_override.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_string_destroy_override.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_string_new_from_array_override.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/error.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/hash_table_generators.c

CBMCFLAGS +=

DEFINES += -DHASH_ITER_ELEMENT_GENERATOR=hash_iterator_string_string_generator
DEFINES += -DHASH_TABLE_FIND_ELEMENT_GENERATOR=hash_find_string_string_generator
DEFINES += -DMAX_NUM_ELEMS=$(MAX_NUM_ELEMS)

PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/proof_allocators.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/utils.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/byte_buf.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/common.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/math.c
PROJECT_SOURCES += $(SRCDIR)/source/enc_ctx.c

HARNESS_ENTRY = aws_cryptosdk_enc_ctx_clone_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(HARNESS_FILE)

REMOVE_FUNCTION_BODY += aws_string_destroy
REMOVE_FUNCTION_BODY += aws_string_new_from_array

UNWINDSET += aws_cryptosdk_enc_ctx_clone.0:$(shell echo $$(($(MAX_NUM_ELEMS) + 1)))
UNWINDSET += aws_cryptosdk_enc_ctx_clone.1:$(shell echo $$(($(MAX_NUM_ELEMS) + 1)))

###########
include ../Makefile.common
