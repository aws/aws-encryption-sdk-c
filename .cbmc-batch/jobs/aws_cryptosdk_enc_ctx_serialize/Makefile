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
#expected runtime: 2m45s
MAX_TABLE_SIZE ?= 2

#A table has 10 words for the struct, plus 3 words for each entry
TABLE_SIZE_IN_WORDS=$(shell echo $$(($$((3 * $(MAX_TABLE_SIZE))) + 10)))

#########
# Vars for Makefile.common

ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/aws_byte_buf_write_stub.c
ABSTRACTIONS += $(SRCDIR)/helper-stubs/aws_array_list_sort_noop_stub.c
ABSTRACTIONS += $(SRCDIR)/helper-stubs/aws_cryptosdk_enc_ctx_size_stub.c
ABSTRACTIONS += $(SRCDIR)/helper-stubs/aws_cryptosdk_hash_elems_array_init_stub.c

ADDITIONAL_REMOVE_FUNCTION_BODY += --remove-function-body aws_array_list_sort
ADDITIONAL_REMOVE_FUNCTION_BODY += --remove-function-body aws_byte_buf_write
ADDITIONAL_REMOVE_FUNCTION_BODY += --remove-function-body aws_cryptosdk_enc_ctx_size
ADDITIONAL_REMOVE_FUNCTION_BODY += --remove-function-body aws_cryptosdk_hash_elems_array_init

CBMCFLAGS +=

DEFINES += -DAWS_CRYPTOSDK_HASH_ELEMS_ARRAY_INIT_GENERATOR=array_list_item_generator
DEFINES += -DMAX_TABLE_SIZE=$(MAX_TABLE_SIZE)
DEFINES += -DMEMCPY_STUB_MAX=128

DEPENDENCIES += $(SRCDIR)/c-common-helper-src/make_common_data_structures.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/proof_allocators.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/utils.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-stubs/error.c
DEPENDENCIES += $(SRCDIR)/c-common-src/byte_buf.c
DEPENDENCIES += $(SRCDIR)/c-common-src/common.c
DEPENDENCIES += $(SRCDIR)/c-common-src/hash_table.c
DEPENDENCIES += $(SRCDIR)/c-common-src/math.c
DEPENDENCIES += $(SRCDIR)/c-common-src/string.c
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/enc_ctx.c

ENTRY = aws_cryptosdk_enc_ctx_serialize_harness


UNWINDSET += array_list_item_generator.0:$(shell echo $$((1 + $(MAX_TABLE_SIZE))))
UNWINDSET += aws_cryptosdk_enc_ctx_serialize.0:$(shell echo $$((1 + $(MAX_TABLE_SIZE))))

###########

include ../Makefile.common
