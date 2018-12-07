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

/**
 * @defgroup Error codes
 * @{
 */

/**
 * CryptoSDK specific error codes. Note that we also make use of error codes defined in the aws-c-common library
 */
enum aws_cryptosdk_err {
    /** The ciphertext was malformed or corrupt */
    AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT = 0x2000,
    /** An unknown internal error has occurred */
    AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN,
    /** An unsupported format version was encountered on decrypt */
    AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT,
    /** KMS returned an error */
    AWS_CRYPTOSDK_ERR_KMS_FAILURE,
    /** A function was called on an object in the wrong state */
    AWS_CRYPTOSDK_ERR_BAD_STATE,
    /** The failing call attempted to exceed a hard limit of some sort I*/
    AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED,
    /** No keyrings were able to decrypt the message in question */
    AWS_CRYPTOSDK_ERR_CANNOT_DECRYPT, // TODO - Rename?
    AWS_CRYPTOSDK_ERR_END_RANGE = 0x2400
};

/**
 * Register error strings with the core error reporting APIs. This function is
 * threadsafe and idempotent, and should be called at least once on application
 * startup.
 */
AWS_CRYPTOSDK_API
void aws_cryptosdk_load_error_strings();

#ifdef __cplusplus
}
#endif

/** @} */ // end of doxygen group

#endif
