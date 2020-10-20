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
MAX_TABLE_SIZE ?= 4
# Time on my laptop: 4m50s
#########
#if we don't include the hash_table.c, we don't need to remove their function bodies
ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/aws_hash_table_no_slots_override.c
ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/aws_string_destroy_override.c
ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/aws_string_new_from_array_override.c
ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/error.c
ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/hash_table_generators.c
ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/memcmp_override_no_op.c

CBMCFLAGS +=

DEFINES += -DHASH_ITER_ELEMENT_GENERATOR=hash_iterator_string_string_generator
DEFINES += -DHASH_TABLE_FIND_ELEMENT_GENERATOR=hash_find_string_string_generator
DEFINES += -DMAX_TABLE_SIZE=$(MAX_TABLE_SIZE)

DEPENDENCIES += $(SRCDIR)/c-common-helper-src/make_common_data_structures.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/proof_allocators.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/utils.c
DEPENDENCIES += $(SRCDIR)/c-common-src/byte_buf.c
DEPENDENCIES += $(SRCDIR)/c-common-src/common.c
DEPENDENCIES += $(SRCDIR)/c-common-src/hash_table.c
DEPENDENCIES += $(SRCDIR)/c-common-src/math.c
DEPENDENCIES += $(SRCDIR)/c-common-src/string.c
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/enc_ctx.c

ENTRY = aws_cryptosdk_enc_ctx_clone_harness

REMOVE_FUNCTION_BODIES += --remove-function-body aws_string_destroy
REMOVE_FUNCTION_BODIES += --remove-function-body aws_string_new_from_array

UNWINDSET += aws_cryptosdk_enc_ctx_clone.0:$(shell echo $$((1 + $(MAX_TABLE_SIZE))))
UNWINDSET += aws_cryptosdk_enc_ctx_clone.1:$(shell echo $$((1 + $(MAX_TABLE_SIZE))))
###########
include ../Makefile.common
