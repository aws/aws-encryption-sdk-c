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

include ../Makefile.string

#########
# Local vars

# gets full coverage, runtime for property is 9min. 
MAX_NUM_ITEMS ?= 1
DEFINES += -DMAX_NUM_ITEMS=$(MAX_NUM_ITEMS)

#########
ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/aws_hash_table_no_slots_override.c
ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/aws_string_destroy_override.c
ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/error.c
ABSTRACTIONS += $(SRCDIR)/helper-src/openssl/bn_override.c
ABSTRACTIONS += $(SRCDIR)/helper-src/openssl/ec_override.c
ABSTRACTIONS += $(SRCDIR)/helper-src/openssl/evp_override.c

# Enable after https://github.com/diffblue/cbmc/issues/5344 is fixed
#AWS_DEEP_CHECKS = 1

CBMCFLAGS +=

DEPENDENCIES += $(SRCDIR)/c-common-helper-src/make_common_data_structures.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/proof_allocators.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/utils.c
DEPENDENCIES += $(SRCDIR)/c-common-src/byte_buf.c
DEPENDENCIES += $(SRCDIR)/c-common-src/common.c
DEPENDENCIES += $(SRCDIR)/c-common-src/math.c
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/materials.c
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/keyring_trace.c
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/edk.c
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/cipher_openssl.c
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/cipher.c
DEPENDENCIES += $(SRCDIR)/helper-src/cbmc_invariants.goto
DEPENDENCIES += $(SRCDIR)/helper-src/make_common_data_structures.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-uninline/atomics.c

ENTRY = aws_cryptosdk_enc_materials_destroy_harness


UNWINDSET += aws_cryptosdk_edk_list_clear.0:$(call addone,$(MAX_NUM_ITEMS)) 
UNWINDSET += aws_cryptosdk_edk_list_elements_are_bounded.0:$(call addone,$(MAX_NUM_ITEMS))
UNWINDSET += aws_cryptosdk_edk_list_elements_are_valid.0:$(call addone,$(MAX_NUM_ITEMS))
UNWINDSET += aws_cryptosdk_edk_list_is_bounded.0:$(call addone,$(MAX_NUM_ITEMS))
UNWINDSET += aws_cryptosdk_edk_list_is_valid.0:$(call addone,$(MAX_NUM_ITEMS)) 
UNWINDSET += aws_cryptosdk_keyring_trace_clear.0:$(call addone,$(MAX_NUM_ITEMS))
UNWINDSET += aws_cryptosdk_keyring_trace_is_valid.0:$(call addone,$(MAX_NUM_ITEMS))
UNWINDSET += ensure_cryptosdk_edk_list_has_allocated_list_elements.0:$(call addone,$(MAX_NUM_ITEMS))
UNWINDSET += ensure_cryptosdk_edk_list_has_allocated_members.0:$(call addone,$(MAX_NUM_ITEMS))
UNWINDSET += ensure_trace_has_allocated_records.0:$(call addone,$(MAX_NUM_ITEMS))

###########
include ../Makefile.common
