/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not
 * use this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#ifndef AWS_CRYPTOSDK_PRIVATE_HKDF_H
#define AWS_CRYPTOSDK_PRIVATE_HKDF_H

#include <aws/common/byte_buf.h>

enum aws_cryptosdk_sha_version {
    AWS_CRYPTOSDK_NOSHA,
    AWS_CRYPTOSDK_SHA256,
    AWS_CRYPTOSDK_SHA384,
    AWS_CRYPTOSDK_SHA512
};

/*
 * This function performs the HKDF extract then expand steps as described in
 * RFC-5869. The length of the okm (output keying material) is required to be
 * set by the user ahead of time and must be less than or equal to 255*HashLen.
 */
int aws_cryptosdk_hkdf(
    struct aws_byte_buf *okm,
    enum aws_cryptosdk_sha_version which_sha,
    const struct aws_byte_buf *salt,
    const struct aws_byte_buf *ikm,
    const struct aws_byte_buf *info);

#endif  // AWS_CRYPTOSDK_PRIVATE_HKDF_H
