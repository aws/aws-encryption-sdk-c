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
include ../Makefile.string

# We abstract these functions as manual inspection shows there is no ec_key associated with the PKEY.
ABSTRACTIONS += $(SRCDIR)/helper-stubs/EVP_PKEY_free_no_ec_key_stub.c
ABSTRACTIONS += $(SRCDIR)/helper-stubs/evp_pkey_is_valid_no_ec_key_stub.c

CBMCFLAGS +=

DEPENDENCIES += $(COMMON_HELPERDIR)/stubs/memcpy_override_havoc.goto
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/make_common_data_structures.goto
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/proof_allocators.goto
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/utils.goto
DEPENDENCIES += $(SRCDIR)/c-common-helper-stubs/error.goto
DEPENDENCIES += $(SRCDIR)/c-common-src/byte_buf.goto
DEPENDENCIES += $(SRCDIR)/c-common-src/common.goto
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/cipher.goto
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/cipher_openssl.goto
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/hkdf.goto
DEPENDENCIES += $(SRCDIR)/helper-src/cbmc_invariants.goto
DEPENDENCIES += $(SRCDIR)/helper-src/make_common_data_structures.goto
DEPENDENCIES += $(SRCDIR)/helper-src/openssl/bio_override.goto
DEPENDENCIES += $(SRCDIR)/helper-src/openssl/bn_override.goto
DEPENDENCIES += $(SRCDIR)/helper-src/openssl/ec_override.goto
DEPENDENCIES += $(SRCDIR)/helper-src/openssl/err_override.goto
DEPENDENCIES += $(SRCDIR)/helper-src/openssl/evp_override.goto

ENTRY = aws_cryptosdk_rsa_encrypt_harness

UNWINDSET +=

###########

include ../Makefile.common
