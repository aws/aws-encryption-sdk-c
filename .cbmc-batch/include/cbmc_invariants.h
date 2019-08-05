/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <aws/cryptosdk/cipher.h>

/* The invariants defined in this file are for use within the CBMC proof harnesses. They cannot be called directly in
 * ESDK code because they depend on internal properties of the OpenSSL data structures which are not part of the public
 * API. However, we can check them in the proof harnesses because these properties are modeled in our abstract model of
 * OpenSSL. */

/* Checks that the message-digest context is valid based on the state of its members. */
bool aws_cryptosdk_md_context_is_valid_cbmc(struct aws_cryptosdk_md_context *md_context);

/* Checks that the signing context is valid based on the state of its members. */
bool aws_cryptosdk_sig_ctx_is_valid_cbmc(struct aws_cryptosdk_sig_ctx *sig_ctx);
