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
include ../Makefile.aws_byte_buf

#########
PROOF_UID = aws_cryptosdk_priv_try_gen_key
HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

# Increasing the length of the edk_list or enc_ctx does not improve coverage.
# Therefore, we choose these values for performance. 
MAX_EDK_LIST_ITEMS ?= 1
MAX_TABLE_SIZE ?= 2
MAX_TRACE_LIST_ITEMS ?= 2

DEFINES += -DARRAY_LIST_TYPE="struct aws_cryptosdk_edk"
DEFINES += -DARRAY_LIST_TYPE_HEADER=\"aws/cryptosdk/edk.h\"
DEFINES += -DAWS_CRYPTOSDK_HASH_ELEMS_ARRAY_INIT_GENERATOR=array_list_item_generator
DEFINES += -DAWS_NO_STATIC_IMPL
DEFINES += -DMAX_EDK_LIST_ITEMS=$(MAX_EDK_LIST_ITEMS)
DEFINES += -DMAX_IV_LEN=$(MAX_IV_LEN)
DEFINES += -DMAX_TABLE_SIZE=$(MAX_TABLE_SIZE)
DEFINES += -DMAX_TRACE_LIST_ITEMS=$(MAX_TRACE_LIST_ITEMS)

# The maximum number of objects is set to 2^8 = 256. This option changes that to 2^9. 
# Without this flag, running this proof causes the CBMC error of 
# "too many addressed objects: maximum number of objects is set to 2^n=256 (with n=8);
# use the `--object-bits n` option to increase the maximum number"
# The proof hits the error when the line "rv = aws_cryptosdk_hdr_write(&session->header,
# &actual_size, session->header_copy, session->header_size);" is reached.
CBMC_OBJECT_BITS = 9

PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/byte_buf.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/common.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/hash_table.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/math.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/array_list.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/atomics.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/byte_order.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/error.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/math.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/string.c
PROJECT_SOURCES += $(PROOF_SOURCE)/openssl/bn_override.c
PROJECT_SOURCES += $(PROOF_SOURCE)/openssl/ec_override.c
PROJECT_SOURCES += $(PROOF_SOURCE)/openssl/evp_override.c
PROJECT_SOURCES += $(PROOF_SOURCE)/openssl/rand_override.c
PROJECT_SOURCES += $(SRCDIR)/source/cipher.c
PROJECT_SOURCES += $(SRCDIR)/source/cipher_openssl.c
PROJECT_SOURCES += $(SRCDIR)/source/edk.c
PROJECT_SOURCES += $(SRCDIR)/source/enc_ctx.c
PROJECT_SOURCES += $(SRCDIR)/source/header.c
PROJECT_SOURCES += $(SRCDIR)/source/hkdf.c
PROJECT_SOURCES += $(SRCDIR)/source/keyring_trace.c
PROJECT_SOURCES += $(SRCDIR)/source/list_utils.c
PROJECT_SOURCES += $(SRCDIR)/source/materials.c
PROJECT_SOURCES += $(SRCDIR)/source/session.c
PROJECT_SOURCES += $(SRCDIR)/source/session_encrypt.c
PROJECT_SOURCES += $(SRCDIR)/source/utils.c

PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/proof_allocators.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/utils.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_array_list_defined_type.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_byte_buf_write_stub.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_hash_iter_overrides.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/aws_string_destroy_override.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/error.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/memcmp_override.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/memcpy_override_havoc.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/memset_override_havoc.c
PROOF_SOURCES += $(PROOF_SOURCE)/cbmc_invariants.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(PROOF_STUB)/aws_array_list_sort_noop_stub.c
PROOF_SOURCES += $(PROOF_STUB)/aws_cryptosdk_enc_ctx_size_stub.c
PROOF_SOURCES += $(PROOF_STUB)/aws_cryptosdk_hash_elems_array_init_stub.c
PROOF_SOURCES += $(PROOF_STUB)/aws_default_allocator_stub.c
PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)

REMOVE_FUNCTION_BODY += aws_array_list_get_at_ptr

# We abstract these functions because manual inspection demonstrates that they are unreachable,
# which leads to improvements in coverage metrics
# All functions removed in aws_cryptosdk_sign_header
REMOVE_FUNCTION_BODY += EVP_DecryptUpdate
REMOVE_FUNCTION_BODY += EVP_sha256
REMOVE_FUNCTION_BODY += EVP_sha384
REMOVE_FUNCTION_BODY += EVP_sha512

UNWINDSET += array_list_item_generator.0:$(shell echo $$((1 + $(MAX_TABLE_SIZE))))
UNWINDSET += aws_cryptosdk_edk_list_clear.0:$(call addone,$(MAX_EDK_LIST_ITEMS))
UNWINDSET += aws_cryptosdk_edk_list_elements_are_bounded.0:$(call addone,$(MAX_EDK_LIST_ITEMS))
UNWINDSET += aws_cryptosdk_edk_list_elements_are_valid.0:$(call addone,$(MAX_EDK_LIST_ITEMS))
UNWINDSET += aws_cryptosdk_enc_ctx_serialize.0:$(shell echo $$((1 + $(MAX_TABLE_SIZE))))
UNWINDSET += aws_cryptosdk_hdr_size.0:$(call addone,$(MAX_EDK_LIST_ITEMS)) 
UNWINDSET += aws_cryptosdk_hdr_write.0:$(call addone,$(MAX_EDK_LIST_ITEMS)) 
UNWINDSET += aws_cryptosdk_keyring_trace_clear.0:$(call addone,$(MAX_TRACE_LIST_ITEMS))
UNWINDSET += aws_cryptosdk_keyring_trace_is_valid.0:$(call addone,$(MAX_TRACE_LIST_ITEMS))
UNWINDSET += aws_cryptosdk_transfer_list.4.0:$(call addone,$(MAX_TRACE_LIST_ITEMS))
UNWINDSET += ensure_cryptosdk_edk_list_has_allocated_list_elements.0:$(call addone,$(MAX_EDK_LIST_ITEMS))
UNWINDSET += ensure_trace_has_allocated_records.0:$(call addone,$(MAX_TRACE_LIST_ITEMS))
UNWINDSET += memcmp.0:$(call addone,$(MAX_BUFFER_SIZE))

###########
include ../Makefile.common
