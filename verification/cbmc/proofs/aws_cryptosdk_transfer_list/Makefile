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

#########
# Local vars
NUM_ELEMS = 2
ITEM_SIZE = 4
# Sufficient to get full coverage. 2,4 takes 11 min on my machine

#########

PROOF_UID = aws_cryptosdk_transfer_list

HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

CBMCFLAGS +=

DEFINES += -DARRAY_LIST_TYPE="struct aws_cryptosdk_edk"
DEFINES += -DARRAY_LIST_TYPE_HEADER=\"aws/cryptosdk/edk.h\"
DEFINES += -DAWS_NO_STATIC_IMPL
DEFINES += -DITEM_SIZE=$(ITEM_SIZE)
DEFINES += -DNUM_ELEMS=$(NUM_ELEMS)

PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/array_list.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/byte_buf.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/common.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/math.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/array_list.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/error.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/math.c
PROJECT_SOURCES += $(SRCDIR)/source/list_utils.c

PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/proof_allocators.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/utils.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/error.c
PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_data_structures.c

# The original aws_array_list_is_valid() has a 64 bit multiplication.
# CBMC performance dies trying to do all those multiplications.
# Replace with a stub until we can fix this issue.
REMOVE_FUNCTION_BODY += aws_array_list_is_valid

UNWINDSET += aws_cryptosdk_transfer_list.4:$(call addone,$(NUM_ELEMS))
###########
include ../Makefile.common
