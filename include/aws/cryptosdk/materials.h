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

#ifndef AWS_CRYPTOSDK_MATERIALS_H
#define AWS_CRYPTOSDK_MATERIALS_H

#include <aws/common/common.h>
#include <aws/common/array_list.h>
#include <aws/common/byte_buf.h>
#include <aws/common/hash_table.h>

#ifndef MAX_DATA_KEY_SIZE
#define MAX_DATA_KEY_SIZE 32
#endif

struct aws_cryptosdk_unencrypted_data_key {
    struct aws_allocator * alloc;
    uint8_t bytes[MAX_DATA_KEY_SIZE];
};

struct aws_cryptosdk_encrypted_data_key {
    struct aws_allocator * alloc;
    struct aws_byte_buf provider_id;
    struct aws_byte_buf provider_info;
    struct aws_cryptosdk_master_key * master;
    uint8_t bytes[MAX_DATA_KEY_SIZE];
};


struct aws_cryptosdk_master_key {
    struct aws_allocator * alloc;
    struct aws_byte_buf provider_id;
    struct aws_byte_buf key_id;

    /**
     * On success, allocates both unencrypted and encrypted key.
     */
    int (*generate_data_key)(struct aws_cryptosdk_master_key * self,
                             struct aws_cryptosdk_unencrypted_data_key ** unencrypted_data_key,
                             struct aws_cryptosdk_encrypted_data_key ** encrypted_data_key,
                             struct aws_common_hash_table * enc_context,
                             uint16_t alg_id);

    /**
     * On success, allocates encrypted data key.
     */
    int (*encrypt_data_key)(struct aws_cryptosdk_master_key * self,
                            const struct aws_cryptosdk_unencrypted_data_key * unencrypted_data_key,
                            struct aws_cryptosdk_encrypted_data_key ** encrypted_data_key,
                            struct aws_common_hash_table * enc_context,
                            uint16_t alg_id);

    /**
     * On success, allocates unencrypted data key.
     */
    int (*decrypt_data_key)(struct aws_cryptosdk_master_key * self,
                            struct aws_cryptosdk_unencrypted_data_key ** unencrypted_data_key,
                            const struct aws_cryptosdk_encrypted_data_key * encrypted_data_key,
                            struct aws_common_hash_table * enc_context,
                            uint16_t alg_id);
};

struct aws_cryptosdk_key_pair {
    // FIXME: implement
};

struct aws_cryptosdk_encryption_materials {
    struct aws_allocator * alloc;
    struct aws_cryptosdk_unencrypted_data_key * unencrypted_data_key;
    struct aws_array_list encrypted_data_keys; // list of struct aws_cryptosdk_encrypted_data_key objects
    struct aws_common_hash_table * enc_context;
    struct aws_cryptosdk_key_pair * trailing_signature_key;
    uint16_t alg_id;
};

struct aws_cryptosdk_decryption_materials {
    struct aws_allocator * alloc;
    struct aws_cryptosdk_unencrypted_data_key * unencrypted_data_key;
    struct aws_cryptosdk_key_pair * trailing_signature_key;
};

struct aws_cryptosdk_materials_manager {
    struct aws_allocator * alloc;
    struct aws_array_list master_keys; // list of struct aws_cryptosdk_master_key objects

    /* FIXME? should struct aws_cryptosdk_alg_properties be moved from session to here?
     * Or some other enum for algorithm?
     */
    uint16_t alg_id;

    /**
     * Uses the allocator, master key list, and algorithm ID specified in the materials manager
     * to generate the encryption materials. On success, allocates encryption materials object
     * and puts address at encryption_materials. If plaintext_size is nonzero, it may be used
     * in determining the encryption materials. If it is zero, it will be ignored.
     */
    int (*generate_encryption_materials)(struct aws_cryptosdk_materials_manager * self,
                                         struct aws_cryptosdk_encryption_materials ** encryption_materials,
                                         struct aws_common_hash_table * enc_context,
                                         size_t plaintext_size);

    /**
     * Checks whether any of the provided list of encrypted data keys can be decrypted by the
     * materials manager. On success, allocates decryption materials object and puts address at
     * decryption_materials.
     */
    int (*generate_decryption_materials)(struct aws_cryptosdk_materials_manager * self,
                                         struct aws_cryptosdk_decryption_materials ** decryption_materials,
                                         const struct aws_array_list * encrypted_data_keys,
                                         struct aws_common_hash_table * enc_context);

};

#endif // AWS_CRYPTOSDK_MATERIALS_H
