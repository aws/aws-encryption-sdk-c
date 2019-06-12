/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <aws/cryptosdk/private/cipher.h>

void aws_cryptosdk_md_size_harness() {
    /* arguments */
    enum aws_cryptosdk_md_alg md_alg;

    /* operation under verification */
    size_t size = aws_cryptosdk_md_size(md_alg);

    /* assertions */
    if (md_alg == AWS_CRYPTOSDK_MD_SHA512) {
        assert(size == (512 / 8));  // number of bytes of a SHA-512 hash
    } else {
        assert(size == 0);  // other algorithms not currently supported
    }
}
