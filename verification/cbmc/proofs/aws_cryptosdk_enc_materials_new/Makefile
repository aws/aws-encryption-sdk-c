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

include ../Makefile.string

KEYRING_TRACE_SIZE = 10 # Value is hardcoded in aws_cryptosdk_keyring_trace_init
# Expected runtime 38sec

ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/error.c
ABSTRACTIONS += $(SRCDIR)/c-common-helper-stubs/aws_hash_table_no_slots_override.c
ABSTRACTIONS += $(SRCDIR)/helper-src/openssl/ec_override.c
ABSTRACTIONS += $(SRCDIR)/helper-src/openssl/bn_override.c
ABSTRACTIONS += $(SRCDIR)/helper-src/openssl/evp_override.c

AWS_DEEP_CHECKS = 1

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
DEPENDENCIES += $(SRCDIR)/helper-src/make_common_data_structures.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-uninline/atomics.c

REMOVE_FUNCTION_BODY += --remove-function-body aws_array_list_get_at_ptr
REMOVE_FUNCTION_BODY += --remove-function-body aws_cryptosdk_edk_is_valid
REMOVE_FUNCTION_BODY += --remove-function-body aws_cryptosdk_edk_clean_up
REMOVE_FUNCTION_BODY += --remove-function-body aws_cryptosdk_keyring_trace_record_is_valid
REMOVE_FUNCTION_BODY += --remove-function-body aws_cryptosdk_sig_ctx_is_valid

ENTRY = aws_cryptosdk_enc_materials_new_harness

UNWINDSET += aws_cryptosdk_keyring_trace_is_valid.0:$(shell echo $$(($(KEYRING_TRACE_SIZE) + 1)))

include ../Makefile.common
