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

/* 
 * Basic error reporting infrastructure. Much of this will likely move to some shared
 * library later.
 */

/*
 * CryptoSDK specific
 */
enum aws_cryptosdk_err {
    // TODO - reserve a range of error codes
    AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT = 0x2000,
    AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN = 0x2001,
    AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT = 0x2002,
    AWS_CRYPTOSDK_ERR_END_RANGE = 0x2800
};

/**
 * Register error strings with the core error reporting APIs.
 */
void aws_cryptosdk_err_init_strings();


#endif
