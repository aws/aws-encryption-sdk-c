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

#Expected runtime on my laptop: 5m30s
#########
# Local vars
MAX_NUM_ELEMS = 2

#########
#if we don't include the hash_table.c, we don't need to remove their function bodies
ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/aws_byte_cursor_read_be16_override.c
ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/aws_hash_table_no_slots_override.c
ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/aws_string_destroy_override.c
ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/aws_string_new_from_array_override.c

CBMCFLAGS +=

DEFINES += -DAWS_BYTE_CURSOR_READ_BE16_GENERATOR=aws_byte_cursor_read_be16_generator_for_enc_ctx_deserialize
DEFINES += -DMAX_NUM_ELEMS=$(MAX_NUM_ELEMS)

DEPENDENCIES += $(SRCDIR)/c-common-helper-src/make_common_data_structures.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/proof_allocators.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/utils.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-stubs/error.c
DEPENDENCIES += $(SRCDIR)/c-common-src/byte_buf.c
DEPENDENCIES += $(SRCDIR)/c-common-src/common.c
DEPENDENCIES += $(SRCDIR)/c-common-src/math.c
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/enc_ctx.c

ENTRY = aws_cryptosdk_enc_ctx_deserialize_harness

REMOVE_FUNCTION_BODIES += --remove-function-body aws_byte_cursor_read_be16
REMOVE_FUNCTION_BODIES += --remove-function-body aws_string_destroy
REMOVE_FUNCTION_BODIES += --remove-function-body aws_string_new_from_array

UNWINDSET += aws_cryptosdk_enc_ctx_deserialize.0:$(shell echo $$(($(MAX_NUM_ELEMS) + 1)))

###########
include ../Makefile.common
