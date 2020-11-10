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
NUM_ELEMS = 2
#2: 2m

#########
PROOF_SOURCES += $(COMMON_PROOF_STUB)/error.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/memcmp_override_no_op.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_array_list_defined_type.c

#DEFINES += -DAWS_DEEP_CHECKS = 1

CBMCFLAGS +=

DEFINES += -DNUM_ELEMS=$(NUM_ELEMS)
DEFINES += -DARRAY_LIST_TYPE="struct aws_cryptosdk_edk"
DEFINES += -DAWS_NO_STATIC_IMPL
DEFINES += -DARRAY_LIST_TYPE_HEADER=\"aws/cryptosdk/edk.h\"

PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/proof_allocators.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/utils.c
PROOF_SOURCES += $(COMMON_PROOF_UNINLINE)/array_list.c
PROOF_SOURCES += $(COMMON_PROOF_UNINLINE)/math.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/byte_buf.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/common.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/math.c
PROJECT_SOURCES += $(SRCDIR)/source/edk.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_data_structures.c

HARNESS_ENTRY = aws_cryptosdk_edk_list_clear_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(HARNESS_FILE)

REMOVE_FUNCTION_BODY += aws_array_list_get_at_ptr
REMOVE_FUNCTION_BODY += nondet_compare


UNWINDSET += aws_cryptosdk_edk_list_clear.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += aws_cryptosdk_edk_list_elements_are_bounded.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += aws_cryptosdk_edk_list_elements_are_valid.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += aws_cryptosdk_edk_list_is_bounded.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += aws_cryptosdk_edk_list_is_valid.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += ensure_cryptosdk_edk_list_has_allocated_list_elements.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += ensure_cryptosdk_edk_list_has_allocated_members.0:$(call addone,$(NUM_ELEMS))
###########
include ../Makefile.common
