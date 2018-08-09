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
#ifndef AWS_CRYPTOSDK_TESTS_LIB_RAW_AES_KR_TEST_VECTORS_H
#define AWS_CRYPTOSDK_TESTS_LIB_RAW_AES_KR_TEST_VECTORS_H

#include <aws/cryptosdk/materials.h>

/**
 * Instantiate the raw AES KR that was used to generate the test vectors.
 */
struct aws_cryptosdk_kr * raw_aes_kr_tv_new(
    struct aws_allocator * alloc,
    enum aws_cryptosdk_aes_key_len raw_key_len);

/**
 * Holds the data for one unencrypted/encrypted data key pair produced by the
 * raw AES KR with the settings above.
 */
struct raw_aes_kr_test_vector {
    enum aws_cryptosdk_aes_key_len raw_key_len;
    enum aws_cryptosdk_alg_id alg;
    const uint8_t * data_key;
    size_t data_key_len;
    const uint8_t * iv;
    const uint8_t * edk_bytes;
    size_t edk_bytes_len;
    const char ** ec_keys;
    const char ** ec_vals;
    size_t num_ec_kv_pairs;
};

extern struct raw_aes_kr_test_vector raw_aes_kr_test_vectors[];

/**
 * Add all of the key-value pairs for this test vector to the encryption context.
 * Assumes encryption context hash table has already been initialized.
 *
 * Warnings: current implementation only allows C-strings with no null bytes
 * in the encryption context. Also on a memory allocation error, it is possible
 * that some but not all pairs may have already been added to the table. But
 * this is just test code, Jack.
 */
int set_test_vector_encryption_context(struct aws_allocator * alloc,
                                       struct aws_hash_table * enc_context,
                                       const struct raw_aes_kr_test_vector * tv);

/**
 * Construct EDK that would be made by the raw AES KR that generated the test
 * vectors with these specific encrypted data key bytes and IV. Note that edk_bytes
 * is the concatenation of the encrypted data key and the AES-GCM tag, and edk_len
 * is the full concatenated length. Because AES-GCM produces cipher that is the same
 * length as plain, the edk_len will be the length of the unencrypted data key
 * (determined by the algorithm suite) plus 16 extra bytes.
 *
 * This function does initialize memory to one of the byte buffers, so it should be
 * released afterward in one of three ways:
 *
 * (1) Push the EDK onto the list of EDKs in a struct aws_cryptosdk_encryption_materials.
 *     Then a call to aws_cryptosdk_encryption_materials_destroy will release it.
 *
 * (2) Push the EDK onto your own struct aws_array_list that holds EDKs, and then use
 *     aws_cryptosdk_edk_list_clean_up to release the list.
 *
 * (3) Deallocate the EDK directly with aws_cryptosdk_edk_clean_up.
 */
struct aws_cryptosdk_edk build_test_edk_init(const uint8_t * edk_bytes, size_t edk_len, const uint8_t * iv);

/**
 * Convenience wrappers around build_test_edk_init that give the EDK of any test vector.
 */
struct aws_cryptosdk_edk edk_init_from_test_vector(struct raw_aes_kr_test_vector * tv);
struct aws_cryptosdk_edk edk_init_from_test_vector_idx(int idx);

/**
 * Returns true if the contents of all EDK byte buffers are identical, false otherwise.
 */
static inline bool aws_cryptosdk_edk_eq(const struct aws_cryptosdk_edk * a, const struct aws_cryptosdk_edk * b) {
    return aws_byte_buf_eq(&a->enc_data_key, &b->enc_data_key) &&
        aws_byte_buf_eq(&a->provider_info, &b->provider_info) &&
        aws_byte_buf_eq(&a->provider_id, &b->provider_id);
}

#endif // AWS_CRYPTOSDK_TESTS_LIB_RAW_AES_KR_TEST_VECTORS_H
