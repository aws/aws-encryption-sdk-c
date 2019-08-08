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

UNWINDSET += strcmp.0:11, aws_base64_decode.0:16

# Added check for memory leaks
CBMCFLAGS += --memory-leak-check

ENTRY = aws_cryptosdk_sig_verify_start_harness

DEPENDENCIES +=	$(SRCDIR)/c-common-helper-src/make_common_data_structures.goto
DEPENDENCIES +=	$(SRCDIR)/c-common-helper-src/proof_allocators.goto
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/utils.goto
DEPENDENCIES +=	$(SRCDIR)/c-common-src/byte_buf.goto
DEPENDENCIES +=	$(SRCDIR)/c-common-src/common.goto
DEPENDENCIES +=	$(SRCDIR)/c-common-src/encoding.goto
DEPENDENCIES +=	$(SRCDIR)/c-common-src/error.goto
DEPENDENCIES +=	$(SRCDIR)/c-enc-sdk-src/cipher.goto
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/cipher_openssl.goto
DEPENDENCIES +=	$(SRCDIR)/helper-src/cbmc_invariants.goto
DEPENDENCIES += $(SRCDIR)/helper-src/make_common_data_structures.goto
DEPENDENCIES += $(SRCDIR)/helper-src/openssl/bn_override.goto
DEPENDENCIES += $(SRCDIR)/helper-src/openssl/ec_override.goto
DEPENDENCIES += $(SRCDIR)/helper-src/openssl/evp_override.goto
DEPENDENCIES += $(SRCDIR)/helper-src/openssl/objects_override.goto

###########

include ../Makefile.common
