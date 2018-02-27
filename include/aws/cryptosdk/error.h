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
#define AWS_CRYPTOSDK_ERROR_H 1

/* 
 * Basic error reporting infrastructure. Much of this will likely move to some shared
 * library later.
 */

/*
 * Common error code definitions
 */
#define AWS_ERR_OK 0
#define AWS_ERR_OOM 0x0001
#define AWS_ERR_UNKNOWN 0x0002
#define AWS_ERR_TRUNCATED 0x0003
#define AWS_ERR_BAD_ARG 0x0003

/*
 * CryptoSDK specific
 */
#define AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT 0x4000

#endif
