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

CBMCFLAGS +=

# aws_atomic_fetch_add_explicit receives a volatile input, which is always model
# as non-deterministic in CBMC; thus, we need a deterministic stub for it
ABSTRACTIONS += $(LINKFARM)/helper-stubs/aws_atomic_fetch_add_explicit.c
REMOVE_FUNCTION_BODY += --remove-function-body aws_atomic_fetch_add_explicit

ABSTRACTIONS += $(LINKFARM)/helper-stubs/aws_atomic_load_int.c
REMOVE_FUNCTION_BODY += --remove-function-body aws_atomic_load_int

ABSTRACTIONS += $(LINKFARM)/helper-stubs/aws_atomic_priv_xlate_order.c
REMOVE_FUNCTION_BODY += --remove-function-body aws_atomic_priv_xlate_order

DEPENDENCIES += $(SRCDIR)/c-common-helper-src/make_common_data_structures.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/proof_allocators.c
DEPENDENCIES += $(SRCDIR)/c-common-src/common.c
DEPENDENCIES += $(SRCDIR)/c-common-src/error.c
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/materials.c
DEPENDENCIES += $(SRCDIR)/helper-src/make_common_data_structures.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-uninline/atomics.c

ENTRY = aws_cryptosdk_keyring_retain_harness

UNWINDSET +=

include ../Makefile.common
