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
include ../Makefile.aws_array_list
include ../Makefile.aws_byte_buf

# Expect runtime for this proof is 3min with these local variables
MAX_TABLE_SIZE ?= 2
DEFINES += -DMAX_TABLE_SIZE=$(MAX_TABLE_SIZE)

NUM_ELEMS = 1
DEFINES += -DNUM_ELEMS=$(NUM_ELEMS)

DEFINES += -DARRAY_LIST_TYPE="struct aws_cryptosdk_keyring_trace_record"
DEFINES += -DAWS_NO_STATIC_IMPL
DEFINES += -DARRAY_LIST_TYPE_HEADER=\"aws/cryptosdk/keyring_trace.h\"

CBMCFLAGS +=

PROOF_SOURCES += $(COMMON_PROOF_STUB)/error.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_array_list_defined_type.c

PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/proof_allocators.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/utils.c

PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/array_list.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/atomics.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/math.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/string.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/error.c

PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/array_list.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/byte_buf.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/error.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/common.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/hash_table.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/math.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/string.c

PROJECT_SOURCES += $(SRCDIR)/source/cipher.c
PROJECT_SOURCES += $(SRCDIR)/source/edk.c
PROJECT_SOURCES += $(SRCDIR)/source/keyring_trace.c
PROJECT_SOURCES += $(SRCDIR)/source/materials.c

PROOF_SOURCES += $(PROOF_SOURCE)/make_common_data_structures.c

HARNESS_ENTRY = aws_cryptosdk_keyring_on_decrypt_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(HARNESS_FILE)

# memcmp is invoked to compare two aws_byte_buf objetcs,
# so the upper bound limit is the size of aws_byte_buf + 1
UNWINDSET += memcmp.0:33
UNWINDSET += aws_cryptosdk_keyring_trace_is_valid.0:$(call addone,$(MAX_ITEM_SIZE))
UNWINDSET += ensure_trace_has_allocated_records.0:$(call addone,$(MAX_ITEM_SIZE))
UNWINDSET += aws_cryptosdk_edk_list_elements_are_bounded.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += aws_cryptosdk_edk_list_elements_are_valid.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += aws_cryptosdk_edk_list_is_bounded.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += aws_cryptosdk_edk_list_is_valid.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += ensure_cryptosdk_edk_list_has_allocated_list_elements.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += ensure_cryptosdk_edk_list_has_allocated_members.0:$(call addone,$(NUM_ELEMS))

include ../Makefile.common
