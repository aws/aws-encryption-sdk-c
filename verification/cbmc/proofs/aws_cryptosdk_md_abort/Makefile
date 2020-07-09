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

UNWINDSET +=

# Adds check for memory leaks for this proof
# Turning this flag on globally would require all proofs to carefully release objects, which they don't do.
# But might as well do it when its easy
CBMCFLAGS += --memory-leak-check

HARNESS_ENTRY = aws_cryptosdk_md_abort_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(HARNESS_FILE)

PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/proof_allocators.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/common.c
PROJECT_SOURCES += $(SRCDIR)/source/cipher_openssl.c
PROOF_SOURCES += $(PROOF_SOURCE)/cbmc_invariants.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(PROOF_SOURCE)/openssl/bn_override.c
PROOF_SOURCES += $(PROOF_SOURCE)/openssl/ec_override.c
PROOF_SOURCES += $(PROOF_SOURCE)/openssl/evp_override.c

###########

include ../Makefile.common
