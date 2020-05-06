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
include ../Makefile.aws_byte_buf

# Use a smaller bound for buffer so the proof runs on a reasonable time
# Expected runtime is 2min for this bound
MAX_BUFFER_SIZE = 4

UNWINDSET += aws_cryptosdk_decrypt_body.0:$(shell echo $$((1 + $(MAX_BUFFER_SIZE))))
# This bound must be 37 because it process a string of fixed size in update_frame_aad
UNWINDSET += strlen.0:37

CBMCFLAGS +=

ENTRY = aws_cryptosdk_decrypt_body_harness

DEPENDENCIES += $(SRCDIR)/c-common-helper-src/make_common_data_structures.goto
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/proof_allocators.goto
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/utils.goto
DEPENDENCIES += $(SRCDIR)/c-common-src/byte_buf.goto
DEPENDENCIES += $(SRCDIR)/c-common-src/common.goto
DEPENDENCIES += $(SRCDIR)/c-common-src/error.goto
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/cipher.goto
DEPENDENCIES += $(SRCDIR)/helper-src/make_common_data_structures.goto
DEPENDENCIES += $(SRCDIR)/helper-src/openssl/evp_override.goto
DEPENDENCIES += $(SRCDIR)/helper-src/openssl/err_override.goto

REMOVE_FUNCTION_BODY += --remove-function-body aws_raise_error_private
REMOVE_FUNCTION_BODY += --remove-function-body EVP_EncryptUpdate
REMOVE_FUNCTION_BODY += --remove-function-body EVP_sha256
REMOVE_FUNCTION_BODY += --remove-function-body EVP_sha384
REMOVE_FUNCTION_BODY += --remove-function-body nondet_compare

include ../Makefile.common
