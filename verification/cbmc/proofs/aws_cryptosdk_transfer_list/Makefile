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
NUM_ELEMS = 2
ITEM_SIZE = 4
# Sufficient to get full coverage. 2,4 takes 11 min on my machine

#########
ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/error.c

CBMCFLAGS +=

DEFINES += -DNUM_ELEMS=$(NUM_ELEMS)
DEFINES += -DITEM_SIZE=$(ITEM_SIZE)
DEFINES += -DARRAY_LIST_TYPE="struct aws_cryptosdk_edk"
DEFINES += -DAWS_NO_STATIC_IMPL
DEFINES += -DARRAY_LIST_TYPE_HEADER=\"aws/cryptosdk/edk.h\"

DEPENDENCIES += $(SRCDIR)/c-common-helper-src/make_common_data_structures.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/proof_allocators.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/utils.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-uninline/array_list.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-uninline/error.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-uninline/math.c
DEPENDENCIES += $(SRCDIR)/c-common-src/array_list.c
DEPENDENCIES += $(SRCDIR)/c-common-src/byte_buf.c
DEPENDENCIES += $(SRCDIR)/c-common-src/common.c
DEPENDENCIES += $(SRCDIR)/c-common-src/math.c
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/list_utils.c
DEPENDENCIES += $(SRCDIR)/helper-src/make_common_data_structures.c

ENTRY = aws_cryptosdk_transfer_list_harness

# The original aws_array_list_is_valid() has a 64 bit multiplication.
# CBMC performance dies trying to do all those multiplications.
# Replace with a stub until we can fix this issue.
REMOVE_FUNCTION_BODIES += --remove-function-body aws_array_list_is_valid

UNWINDSET += aws_cryptosdk_transfer_list.4:$(call addone,$(NUM_ELEMS)) 
###########
include ../Makefile.common
