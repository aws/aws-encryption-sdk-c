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

###########
# if Makefile.local exists, use it. This provides a way to override the defaults 
sinclude ../Makefile.local
#otherwise, use the default values
include ../Makefile.local_default

# We abstract these functions as manual inspection shows there is no pkey associated with the MD_ctx.
ABSTRACTIONS += $(SRCDIR)/helper-stubs/EVP_MD_CTX_free_no_pkey_stub.c
ABSTRACTIONS += $(SRCDIR)/helper-stubs/evp_md_ctx_is_valid_no_pkey_stub.c

# Adds check for memory leaks for this proof
# Turning this flag on globally would require all proofs to carefully release objects, which they don't do.
# But might as well do it when its easy
CBMCFLAGS += --memory-leak-check

ENTRY = aws_cryptosdk_md_init_harness

DEPENDENCIES += $(SRCDIR)/c-common-helper-src/proof_allocators.goto
DEPENDENCIES += $(SRCDIR)/c-common-helper-stubs/error.goto
DEPENDENCIES += $(SRCDIR)/c-common-src/common.goto
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/cipher_openssl.goto
DEPENDENCIES += $(SRCDIR)/helper-src/cbmc_invariants.goto
DEPENDENCIES += $(SRCDIR)/helper-src/openssl/bn_override.goto
DEPENDENCIES += $(SRCDIR)/helper-src/openssl/ec_override.goto
DEPENDENCIES += $(SRCDIR)/helper-src/openssl/evp_override.goto

UNWINDSET +=

###########

include ../Makefile.common
