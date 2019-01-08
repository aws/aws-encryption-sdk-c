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
#ifndef AWS_CRYPTOSDK_PRIVATE_RAW_AES_KEYRING_H
#define AWS_CRYPTOSDK_PRIVATE_RAW_AES_KEYRING_H

#include <aws/cryptosdk/raw_aes_keyring.h>

/* Raw AES Keyring always uses AES-GCM encryption with 12 byte IV and 16 byte tag.
 * This is only for the encryption OF data keys, and is separate from the algorithm
 * properties, which are only for encryption WITH data keys.
 */
#define RAW_AES_KR_IV_LEN 12
#define RAW_AES_KR_TAG_LEN 16

/**
 * Allocates the output buffer and writes the provider info for an EDK encrypted
 * by this KR into it. The format is:
 *
 * Master Key ID (variable length)
 * AES-GCM tag length *IN BITS* (4 bytes, big-endian)
 * IV length (4 bytes, big-endian)
 * IV bytes (length determined by previous field)
 */
int aws_cryptosdk_serialize_provider_info_init(
    struct aws_allocator *alloc,
    struct aws_byte_buf *output,
    const struct aws_string *master_key_id,
    const uint8_t *iv);

/**
 * Checks whether the provider info of a particular EDK is compatible with this KR
 * by seeing whether the known Master Key ID, tag length, and IV length are in the
 * provider info and whether the entire buffer has the proper length.
 *
 * If all of the above checks pass, the IV byte buffer is set up to look at the
 * bytes of the IV within the provider info and true is returned.
 *
 * If any of the checks fail, false is returned, signaling that this EDK is not
 * compatible with this KR.
 *
 * No memory is allocated by this function, as the IV buffer does not own its own
 * memory.
 */
bool aws_cryptosdk_parse_provider_info(
    struct aws_cryptosdk_keyring *kr, struct aws_byte_buf *iv, const struct aws_byte_buf *provider_info);

/**
 * Does everything that the raw AES KR's on_encrypt virtual function
 * does except random generation of the data key and IV. For testing with known inputs.
 */
int aws_cryptosdk_raw_aes_keyring_encrypt_data_key_with_iv(
    struct aws_cryptosdk_keyring *kr,
    struct aws_allocator *request_alloc,
    const struct aws_byte_buf *unencrypted_data_key,
    struct aws_array_list *edks,
    const struct aws_hash_table *enc_ctx,
    enum aws_cryptosdk_alg_id alg,
    const uint8_t *iv);

#endif  // AWS_CRYPTOSDK_PRIVATE_RAW_AES_KEYRING_H
