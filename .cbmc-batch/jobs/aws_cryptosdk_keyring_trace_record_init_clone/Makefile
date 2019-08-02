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
sinclude ../Makefile.string

CBMC_UNWINDSET += --unwindset memcmp.0:17

CBMCFLAGS +=

ENTRY = aws_cryptosdk_keyring_trace_record_init_clone

OBJS +=	$(SRCDIR)/c-common-helper-src/make_common_data_structures.goto
OBJS +=	$(SRCDIR)/c-common-helper-src/proof_allocators.goto
OBJS +=	$(SRCDIR)/c-common-src/byte_buf.goto
OBJS +=	$(SRCDIR)/c-common-src/common.goto
OBJS +=	$(SRCDIR)/c-common-src/error.goto
OBJS +=	$(SRCDIR)/c-common-src/string.goto
OBJS +=	$(SRCDIR)/c-enc-sdk-src/cipher.goto
OBJS +=	$(SRCDIR)/c-enc-sdk-src/keyring_trace.goto
OBJS +=	$(SRCDIR)/c-enc-sdk-src/utils.goto
OBJS += $(COMMON_HELPERDIR)/stubs/memcmp_override.goto
OBJS += $(SRCDIR)/$(ENTRY)_harness.goto
OBJS += $(SRCDIR)/helper-src/make_common_data_structures.goto


###########

include ../Makefile.common
