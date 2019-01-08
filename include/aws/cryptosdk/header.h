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

#ifndef AWS_CRYPTOSDK_HEADER_H
#define AWS_CRYPTOSDK_HEADER_H

/**
 * @ingroup session
 * Known algorithm suite names.
 * These follow the format:
 *   [cipher algorithm]_IV[iv length]_AUTH[authtag length]_KD[KDF algorithm]_SIG[Signature algorithm, or NONE]
 */
enum aws_cryptosdk_alg_id {
    ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 = 0x0378,
    ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 = 0x0346,
    ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 = 0x0214,
    ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256  = 0x0178,
    ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256  = 0x0146,
    ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256  = 0x0114,
    ALG_AES256_GCM_IV12_TAG16_NO_KDF    = 0x0078,
    ALG_AES192_GCM_IV12_TAG16_NO_KDF    = 0x0046,
    ALG_AES128_GCM_IV12_TAG16_NO_KDF    = 0x0014
};

#endif  // AWS_CRYPTOSDK_HEADER_H
