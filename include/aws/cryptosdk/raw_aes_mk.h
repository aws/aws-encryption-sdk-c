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
#ifndef AWS_CRYPTOSDK_RAW_AES_MK_H
#define AWS_CRYPTOSDK_RAW_AES_MK_H

#include <aws/cryptosdk/materials.h>

/**
 * A Master Key (MK) which does local AES-GCM encryption and decryption of data keys using
 * the bytes in the array provided as the AES key. In order to maximize security of
 * the raw key bytes, the array is not copied, so the caller is expected to maintain
 * the bytes in memory while this MK is still in use and should zeroize the array when
 * done. THE CALLER OWNS THE RAW KEY BYTES; THIS MK DOES NOT.
 *
 * Master key ID and provider ID provided by the caller are copied into the state of the
 * MK, so those arrays do not need to be maintained while using the MK. The master key
 * ID and provider ID are included as plaintext metadata in the encrypted data key
 * format for keys produced by this MK, and they are checked when this MK attempts to
 * decrypt data keys. In other words, a raw AES MK which attempts to decrypt data
 * previously encrypted by another raw AES MK must have the same master key ID and
 * provider ID. However, they are not authenticated data. They are only a bookkeeping
 * mechanism and provide no additional security.
 *
 * The encryption context which is passed to this MK on encrypt and decrypt calls is
 * used as additional authenticated data (AAD) in the AES-GCM encryption of the data keys.
 * In summary, in order to decrypt data encrypted by another raw AES MK, the decrypt
 * attempt must use a matching master key ID, provider ID, and encryption context, but
 * only the encryption context is used for authentication.
 *
 * On failure returns NULL and sets an internal AWS error code.
 */
struct aws_cryptosdk_mk * aws_cryptosdk_raw_aes_mk_new(struct aws_allocator * alloc,
                                                       const uint8_t * master_key_id,
                                                       size_t master_key_id_len,
                                                       const uint8_t * provider_id,
                                                       size_t provider_id_len,
                                                       const uint8_t raw_key_bytes[32]);

#endif // AWS_CRYPTOSDK_RAW_AES_MK_H
