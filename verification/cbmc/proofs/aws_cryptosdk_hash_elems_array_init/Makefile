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
include ../Makefile.aws_hash_table

# Expected runtime for this harness is 2min

PROOF_UID = aws_cryptosdk_hash_elems_array_init

HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

CBMCFLAGS +=

DEFINES += -DAWS_NO_STATIC_IMPL

# The maximum number of objects is set to 2^8 = 256. This option changes that to 2^9.
# Without this flag, running this proof causes the CBMC error of
# "too many addressed objects: maximum number of objects is set to 2^n=256 (with n=8);
# use the `--object-bits n` option to increase the maximum number"
CBMC_OBJECT_BITS ?= 9

PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/array_list.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/common.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/error.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/hash_table.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/array_list.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/math.c
PROJECT_SOURCES += $(SRCDIR)/source/utils.c

PROOF_SOURCES += $(CBMC_ROOT)/aws-c-common/source/allocator.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/error.c
PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(PROOF_STUB)/aws_add_size_checked.c
PROOF_SOURCES += $(PROOF_STUB)/aws_hash_iter_overrides.c

REMOVE_FUNCTION_BODY += aws_add_size_checked

UNWINDSET += aws_cryptosdk_hash_elems_array_init.0:$(call addone,$(MAX_TABLE_SIZE))

include ../Makefile.common
