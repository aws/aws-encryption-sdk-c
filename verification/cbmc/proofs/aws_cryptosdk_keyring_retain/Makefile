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

# Expect runtime for this proof is 10sec

CBMCFLAGS +=

# aws_atomic_fetch_add_explicit receives a volatile input, which is always model
# as non-deterministic in CBMC; thus, we need a deterministic stub for it
PROOF_SOURCES += $(PROOF_STUB)/aws_atomic_fetch_add_explicit.c
REMOVE_FUNCTION_BODY += aws_atomic_fetch_add_explicit

PROOF_SOURCES += $(PROOF_STUB)/aws_atomic_load_int.c
REMOVE_FUNCTION_BODY += aws_atomic_load_int

PROOF_SOURCES += $(PROOF_STUB)/aws_atomic_priv_xlate_order.c
REMOVE_FUNCTION_BODY += aws_atomic_priv_xlate_order

PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/make_common_data_structures.c
PROOF_SOURCES += $(COMMON_PROOF_SOURCE)/proof_allocators.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/common.c
PROJECT_SOURCES += $(CBMC_ROOT)/aws-c-common/source/error.c
PROJECT_SOURCES += $(SRCDIR)/source/materials.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_data_structures.c
PROJECT_SOURCES += $(COMMON_PROOF_UNINLINE)/atomics.c

HARNESS_ENTRY = aws_cryptosdk_keyring_retain_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(HARNESS_FILE)

UNWINDSET +=

include ../Makefile.common
