/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#ifndef AWS_CRYPTOSDK_CIPHER_H
#define AWS_CRYPTOSDK_CIPHER_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define MAX_DATA_KEY_SIZE 32

struct aws_cryptosdk_data_key {
    uint8_t keybuf[MAX_DATA_KEY_SIZE];
};

static inline void aws_cryptosdk_secure_zero(void *buf, size_t len) {
    memset(buf, 0, len);
    // Perform a compiler memory barrier to ensure that the memset is not eliminated
    __asm__ __volatile__("" :: "r" (buf) : "memory");

    // TODO: MSVC/win32 support using SecureZero
}

#endif // AWS_CRYPTOSDK_CIPHER_H
