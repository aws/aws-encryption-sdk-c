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

###########
include ../Makefile.string
include ../Makefile.aws_array_list

CBMC_UNWINDSET += --unwindset aws_cryptosdk_keyring_trace_is_valid.0:$(shell echo $$((2 + $(MAX_ITEM_SIZE)))),ensure_trace_has_allocated_records.0:$(shell echo $$((1 + $(MAX_ITEM_SIZE)))),aws_string_new_from_array.0:$(shell echo $$((1 + $(MAX_STRING_LEN))))

HARNESS_ENTRY = aws_cryptosdk_keyring_trace_add_record_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(HARNESS_FILE)

PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/proof_allocators.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/utils.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/array_list.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/byte_buf.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/common.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/error.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/string.c
PROJECT_SOURCES += $(SRCDIR)/source/cipher.c
PROJECT_SOURCES += $(SRCDIR)/source/keyring_trace.c
PROJECT_SOURCES += $(SRCDIR)/source/utils.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/memcpy_override_havoc.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_data_structures.c
###########

include ../Makefile.common
