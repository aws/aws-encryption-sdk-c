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

PROOF_UID = aws_cryptosdk_md_update

HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

# Adds check for memory leaks for this proof
# Turning this flag on globally would require all proofs to carefully release objects, which they don't do.
# But might as well do it when its easy
CBMCFLAGS += --memory-leak-check

PROJECT_SOURCES += $(PROOF_SOURCE)/openssl/bn_override.c
PROJECT_SOURCES += $(PROOF_SOURCE)/openssl/ec_override.c
PROJECT_SOURCES += $(PROOF_SOURCE)/openssl/evp_override.c
PROJECT_SOURCES += $(SRCDIR)/source/cipher_openssl.c

PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/proof_allocators.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/utils.c
PROOF_SOURCES += $(COMMON_PROOF_STUB)/error.c
PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/cbmc_invariants.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_data_structures.c
# We abstract these functions as manual inspection shows there is no pkey associated with the MD_ctx.
PROOF_SOURCES += $(PROOF_STUB)/EVP_MD_CTX_free_no_pkey_stub.c
PROOF_SOURCES += $(PROOF_STUB)/evp_md_ctx_is_valid_no_pkey_stub.c

REMOVE_FUNCTION_BODY += EVP_MD_CTX_free
REMOVE_FUNCTION_BODY += evp_md_ctx_is_valid

UNWINDSET +=
###########

include ../Makefile.common
