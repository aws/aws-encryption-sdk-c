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
 * For more information, see the <a
 * href="https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html">Algorithms
 * Reference</a>.
 */
enum aws_cryptosdk_alg_id {
    ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384 = 0x0578,
    ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY            = 0x0478,
    ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 = 0x0378,
    ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 = 0x0346,
    ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 = 0x0214,
    ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256            = 0x0178,
    ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256            = 0x0146,
    ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256            = 0x0114,
    ALG_AES256_GCM_IV12_TAG16_NO_KDF                 = 0x0078,
    ALG_AES192_GCM_IV12_TAG16_NO_KDF                 = 0x0046,
    ALG_AES128_GCM_IV12_TAG16_NO_KDF                 = 0x0014
};

enum aws_cryptosdk_hdr_version { AWS_CRYPTOSDK_HEADER_VERSION_1_0 = 0x01, AWS_CRYPTOSDK_HEADER_VERSION_2_0 = 0x02 };

#endif  // AWS_CRYPTOSDK_HEADER_H
