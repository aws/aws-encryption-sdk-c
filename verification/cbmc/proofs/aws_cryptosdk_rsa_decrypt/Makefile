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

###########
# if Makefile.local exists, use it. This provides a way to override the defaults
sinclude ../Makefile.local
#otherwise, use the default values
include ../Makefile.local_default
include ../Makefile.aws_byte_buf
include ../Makefile.aws_string

# We abstract these functions as manual inspection shows there is no ec_key associated with the PKEY.
PROOF_SOURCES += $(PROOF_STUB)/EVP_PKEY_free_no_ec_key_stub.c
PROOF_SOURCES += $(PROOF_STUB)/evp_pkey_is_valid_no_ec_key_stub.c

CBMCFLAGS +=

PROOF_SOURCES += $(COMMON_PROOF_STUB)/memcpy_override_havoc.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/proof_allocators.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/utils.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/error.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/byte_buf.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/common.c
PROJECT_SOURCES += $(SRCDIR)/source/cipher.c
PROJECT_SOURCES += $(SRCDIR)/source/cipher_openssl.c
PROJECT_SOURCES += $(SRCDIR)/source/hkdf.c
PROOF_SOURCES += $(PROOF_SOURCE)/cbmc_invariants.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_data_structures.c
PROJECT_SOURCES += $(PROOF_SOURCE)/openssl/bio_override.c
PROJECT_SOURCES += $(PROOF_SOURCE)/openssl/bn_override.c
PROJECT_SOURCES += $(PROOF_SOURCE)/openssl/ec_override.c
PROJECT_SOURCES += $(PROOF_SOURCE)/openssl/err_override.c
PROJECT_SOURCES += $(PROOF_SOURCE)/openssl/evp_override.c

HARNESS_ENTRY = aws_cryptosdk_rsa_decrypt_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(HARNESS_FILE)

UNWINDSET +=

REMOVE_FUNCTION_BODY += EVP_PKEY_free
REMOVE_FUNCTION_BODY += evp_pkey_is_valid

###########

include ../Makefile.common
