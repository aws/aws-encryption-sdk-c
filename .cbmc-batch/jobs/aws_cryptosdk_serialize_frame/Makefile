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

## At the moment this is not used in the Makefile.common of encryption-sdk
UNWINDSET += 

CBMCFLAGS +=

ENTRY = aws_cryptosdk_serialize_frame

OBJS += $(SRCDIR)/$(ENTRY)_harness.goto
OBJS +=	$(SRCDIR)/c-enc-sdk-src/framefmt.goto
OBJS +=	$(SRCDIR)/c-enc-sdk-src/cipher.goto
OBJS +=	$(SRCDIR)/c-common-src/common.goto
OBJS +=	$(SRCDIR)/c-common-src/error.goto
OBJS +=	$(SRCDIR)/c-common-src/byte_buf.goto
OBJS += $(SRCDIR)/helper-src/make_common_data_structures.goto
OBJS +=	$(SRCDIR)/c-common-helper-src/make_common_data_structures.goto
OBJS +=	$(SRCDIR)/c-common-helper-src/proof_allocators.goto

###########

include ../Makefile.common
