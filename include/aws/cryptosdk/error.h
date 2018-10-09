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

#ifndef AWS_CRYPTOSDK_ERROR_H
#define AWS_CRYPTOSDK_ERROR_H

#include <aws/common/error.h>
#include <aws/common/common.h>
#include <aws/cryptosdk/exports.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * Basic error reporting infrastructure. Much of this will likely move to some shared
 * library later.
 */

/*
 * CryptoSDK specific
 */
enum aws_cryptosdk_err {
    AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT = 0x2000,
    AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN,
    AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT,
    AWS_CRYPTOSDK_ERR_NO_KEYRINGS_FOUND,
    AWS_CRYPTOSDK_ERR_KMS_FAILURE,
    AWS_CRYPTOSDK_ERR_BAD_STATE,
    AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED,
    AWS_CRYPTOSDK_ERR_CANNOT_DECRYPT, // TODO - Rename?
    AWS_CRYPTOSDK_ERR_END_RANGE = 0x2400
};

/**
 * Register error strings with the core error reporting APIs.
 */
AWS_CRYPTOSDK_API
void aws_cryptosdk_err_init_strings();

#ifdef __cplusplus
}
#endif

#endif
