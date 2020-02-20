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
ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/error.c
ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/memcmp_override_no_op.c
ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/aws_array_list_defined_type.c

#AWS_DEEP_CHECKS = 1

CBMCFLAGS +=

DEFINES += -DNUM_ELEMS=$(NUM_ELEMS)
DEFINES += -DARRAY_LIST_TYPE="struct aws_cryptosdk_edk"
DEFINES += -DAWS_NO_STATIC_IMPL
DEFINES += -DARRAY_LIST_TYPE_HEADER=\"aws/cryptosdk/edk.h\"

DEPENDENCIES += $(SRCDIR)/c-common-helper-src/make_common_data_structures.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/proof_allocators.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/utils.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-uninline/array_list.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-uninline/math.c
DEPENDENCIES += $(SRCDIR)/c-common-src/byte_buf.c
DEPENDENCIES += $(SRCDIR)/c-common-src/common.c
DEPENDENCIES += $(SRCDIR)/c-common-src/math.c
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/edk.c
DEPENDENCIES += $(SRCDIR)/helper-src/make_common_data_structures.c

ENTRY = aws_cryptosdk_edk_list_clean_up_harness

REMOVE_FUNCTION_BODIES += --remove-function-body aws_array_list_get_at_ptr
REMOVE_FUNCTION_BODIES += --remove-function-body nondet_compare

addone = $(shell echo $$(( $(1) + 1)))

UNWINDSET += aws_cryptosdk_edk_list_clear.0:$(call addone,$(NUM_ELEMS)) 
UNWINDSET += aws_cryptosdk_edk_list_elements_are_bounded.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += aws_cryptosdk_edk_list_elements_are_valid.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += aws_cryptosdk_edk_list_is_bounded.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += aws_cryptosdk_edk_list_is_valid.0:$(call addone,$(NUM_ELEMS)) 
UNWINDSET += ensure_cryptosdk_edk_list_has_allocated_list_elements.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += ensure_cryptosdk_edk_list_has_allocated_members.0:$(call addone,$(NUM_ELEMS))
###########
include ../Makefile.common
