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

ABSTRACTIONS += $(SRCDIR)/helper-stubs/aws_hash_iter_overrides.c

ABSTRACTIONS += $(LINKFARM)/helper-stubs/aws_add_size_checked.c
REMOVE_FUNCTION_BODY += --remove-function-body aws_add_size_checked

CBMCFLAGS +=

DEPENDENCIES += $(SRCDIR)/c-common-helper-src/make_common_data_structures.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/proof_allocators.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-uninline/math.c
DEPENDENCIES += $(SRCDIR)/c-common-src/array_list.c
DEPENDENCIES += $(SRCDIR)/c-common-src/hash_table.c
DEPENDENCIES += $(SRCDIR)/c-common-src/common.c
DEPENDENCIES += $(SRCDIR)/c-common-src/error.c
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/utils.c
DEPENDENCIES += $(SRCDIR)/helper-src/make_common_data_structures.c

ENTRY = aws_cryptosdk_hash_elems_array_init_harness

UNWINDSET += aws_cryptosdk_hash_elems_array_init.0:$(call addone,$(MAX_TABLE_SIZE))

include ../Makefile.common
