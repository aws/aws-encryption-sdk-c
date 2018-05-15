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
#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/header.h>

enum aws_cryptosdk_cmm_type {
    CMM_DEFAULT,
    CMM_CACHING,
    CMM_MULTI
};

enum aws_cryptosdk_mkp_type {
    MKP_KMS,
    MKP_KEYSTORE
};

enum aws_cryptosdk_mk_type {
    MK_KMS,
    MK_KEYSTORE
};

struct aws_cryptosdk_mk {
    struct aws_allocator * alloc;
    enum aws_cryptosdk_mk_type type;
    enum aws_cryptosdk_alg_id alg_id;
};

struct aws_cryptosdk_mkp {
    struct aws_allocator * alloc;
    enum aws_cryptosdk_mkp_type type;
    enum aws_cryptosdk_alg_id alg_id;
};

struct aws_cryptosdk_cmm {
    struct aws_allocator * alloc;
    enum aws_cryptosdk_cmm_type type;
    enum aws_cryptosdk_alg_id alg_id;
    struct aws_cryptosdk_mkp * mkp;
};


/* Not sure? */
#define MAX_ENCRYPTED_DATA_KEY_SIZE 64

struct aws_cryptosdk_encrypted_data_key {
    struct aws_cryptosdk_mk * master;
    uint8_t bytes[MAX_ENCRYPTED_DATA_KEY_SIZE];
};

/*
 * Private key stuff is needed for trailing signature. But this should maybe only be in default CMM
 * and not in base structs?
 */
struct aws_cryptosdk_private_key {
    //FIXME: implement
};

struct aws_cryptosdk_public_key {
    //FIXME: implement
};

struct aws_cryptosdk_key_pair {
    struct aws_cryptosdk_private_key private_key;
    struct aws_cryptosdk_public_key public_key;
};

struct aws_cryptosdk_encryption_materials {
    struct aws_allocator * alloc;
    struct aws_cryptosdk_data_key unencrypted_data_key;
    struct aws_array_list encrypted_data_keys; // list of struct aws_cryptosdk_encrypted_data_key objects
    struct aws_hash_table * enc_context;
    struct aws_cryptosdk_key_pair trailing_signature_key_pair;
    enum aws_cryptosdk_alg_id alg_id;
};

struct aws_cryptosdk_decryption_materials {
    struct aws_allocator * alloc;
    struct aws_cryptosdk_data_key unencrypted_data_key;
    struct aws_cryptosdk_public_key trailing_signature_key;
};

struct aws_cryptosdk_cmm_vt {
    size_t size;
    int (*destroy)(struct aws_cryptosdk_cmm * cmm);
    int (*generate_encryption_materials)(struct aws_cryptosdk_cmm * cmm,
                                         struct aws_cryptosdk_encryption_materials ** output,
                                         struct aws_hash_table * enc_context);
    int (*generate_decryption_materials)(struct aws_cryptosdk_cmm * cmm,
                                         struct aws_cryptosdk_decryption_materials ** output,
                                         const struct aws_array_list * encrypted_data_keys,
                                         struct aws_hash_table * enc_context);
};

int aws_cryptosdk_cmm_default_destroy(struct aws_cryptosdk_cmm * cmm);
int aws_cryptosdk_cmm_default_generate_encryption_materials(struct aws_cryptosdk_cmm * cmm,
                                                            struct aws_cryptosdk_encryption_materials ** output,
                                                            struct aws_hash_table * enc_context);
int aws_cryptosdk_cmm_default_generate_decryption_materials(struct aws_cryptosdk_cmm * cmm,
                                                            struct aws_cryptosdk_decryption_materials ** output,
                                                            const struct aws_array_list * encrypted_data_keys,
                                                            struct aws_hash_table * enc_context);

int aws_cryptosdk_cmm_caching_destroy(struct aws_cryptosdk_cmm * cmm);
int aws_cryptosdk_cmm_caching_generate_encryption_materials(struct aws_cryptosdk_cmm * cmm,
                                                            struct aws_cryptosdk_encryption_materials ** output,
                                                            struct aws_hash_table * enc_context);
int aws_cryptosdk_cmm_caching_generate_decryption_materials(struct aws_cryptosdk_cmm * cmm,
                                                            struct aws_cryptosdk_decryption_materials ** output,
                                                            const struct aws_array_list * encrypted_data_keys,
                                                            struct aws_hash_table * enc_context);

int aws_cryptosdk_cmm_multi_destroy(struct aws_cryptosdk_cmm * cmm);
int aws_cryptosdk_cmm_multi_generate_encryption_materials(struct aws_cryptosdk_cmm * cmm,
                                                          struct aws_cryptosdk_encryption_materials ** output,
                                                          struct aws_hash_table * enc_context);
int aws_cryptosdk_cmm_multi_generate_decryption_materials(struct aws_cryptosdk_cmm * cmm,
                                                          struct aws_cryptosdk_decryption_materials ** output,
                                                          const struct aws_array_list * encrypted_data_keys,
                                                          struct aws_hash_table * enc_context);

static struct aws_cryptosdk_cmm_vt aws_cryptosdk_cmm_vt_list[] = {
    {3,
     aws_cryptosdk_cmm_default_destroy,
     aws_cryptosdk_cmm_default_generate_encryption_materials,
     aws_cryptosdk_cmm_default_generate_decryption_materials},
    {3,
     aws_cryptosdk_cmm_caching_destroy,
     aws_cryptosdk_cmm_caching_generate_encryption_materials,
     aws_cryptosdk_cmm_caching_generate_decryption_materials},
    {3,
     aws_cryptosdk_cmm_multi_destroy,
     aws_cryptosdk_cmm_multi_generate_encryption_materials,
     aws_cryptosdk_cmm_multi_generate_decryption_materials}
};

struct aws_cryptosdk_mkp_vt {
    size_t size;
    int (*destroy)(struct aws_cryptosdk_mkp * mkp);
    int (*get_master_keys_for_encryption)(struct aws_cryptosdk_mkp * mkp,
                                          struct aws_array_list ** master_keys, // list of (aws_cryptosdk_mk *)
                                          struct aws_hash_table * enc_context);
    int (*get_master_key)(struct aws_cryptosdk_mkp * mkp,
                          struct aws_cryptosdk_mk ** master_key,
                          const struct aws_byte_buf * provider,
                          const struct aws_byte_buf * key_id);
    int (*decrypt_data_key)(struct aws_cryptosdk_mkp * mkp,
                            struct aws_cryptosdk_data_key * output,
                            const struct aws_array_list * encrypted_data_keys,
                            struct aws_hash_table * enc_context);
};

int aws_cryptosdk_mkp_kms_destroy(struct aws_cryptosdk_mkp * mkp);
int aws_cryptosdk_mkp_kms_get_master_keys_for_encryption(struct aws_cryptosdk_mkp * mkp,
                                                         struct aws_array_list ** master_keys,
                                                         struct aws_hash_table * enc_context);
int aws_cryptosdk_mkp_kms_get_master_key(struct aws_cryptosdk_mkp * mkp,
                                         struct aws_cryptosdk_mk ** master_key,
                                         const struct aws_byte_buf * provider,
                                         const struct aws_byte_buf * key_id);
int aws_cryptosdk_mkp_kms_decrypt_data_key(struct aws_cryptosdk_mkp * mkp,
                                           struct aws_cryptosdk_data_key * output,
                                           const struct aws_array_list * encrypted_data_keys,
                                           struct aws_hash_table * enc_context);

int aws_cryptosdk_mkp_keystore_destroy(struct aws_cryptosdk_mkp * mkp);
int aws_cryptosdk_mkp_keystore_get_master_keys_for_encryption(struct aws_cryptosdk_mkp * mkp,
                                                              struct aws_array_list ** master_keys,
                                                              struct aws_hash_table * enc_context);
int aws_cryptosdk_mkp_keystore_get_master_key(struct aws_cryptosdk_mkp * mkp,
                                              struct aws_cryptosdk_mk ** master_key,
                                              const struct aws_byte_buf * provider,
                                              const struct aws_byte_buf * key_id);
int aws_cryptosdk_mkp_keystore_decrypt_data_key(struct aws_cryptosdk_mkp * mkp,
                                                struct aws_cryptosdk_data_key * output,
                                                const struct aws_array_list * encrypted_data_keys,
                                                struct aws_hash_table * enc_context);


static struct aws_cryptosdk_mkp_vt aws_cryptosdk_mkp_vt_list[] = {
    {4,
     aws_cryptosdk_mkp_kms_destroy,
     aws_cryptosdk_mkp_kms_get_master_keys_for_encryption,
     aws_cryptosdk_mkp_kms_get_master_key,
     aws_cryptosdk_mkp_kms_decrypt_data_key},
    {4,
     aws_cryptosdk_mkp_keystore_destroy,
     aws_cryptosdk_mkp_keystore_get_master_keys_for_encryption,
     aws_cryptosdk_mkp_keystore_get_master_key,
     aws_cryptosdk_mkp_keystore_decrypt_data_key}
};

struct aws_cryptosdk_mk_vt {
    size_t size;
    int (*destroy)(struct aws_cryptosdk_mk * mk);
    int (*generate_data_key)(struct aws_cryptosdk_mk * mk,
                             struct aws_cryptosdk_data_key * unencrypted_data_key,
                             struct aws_cryptosdk_encrypted_data_key * encrypted_data_key);
    int (*encrypt_data_key)(struct aws_cryptosdk_mk * mk,
                            struct aws_cryptosdk_encrypted_data_key * encrypted_data_key,
                            const struct aws_cryptosdk_data_key * unencrypted_data_key);
};

int aws_cryptosdk_mk_kms_destroy(struct aws_cryptosdk_mk * mk);
int aws_cryptosdk_mk_kms_generate_data_key(struct aws_cryptosdk_mk * mk,
                                           struct aws_cryptosdk_data_key * unencrypted_data_key,
                                           struct aws_cryptosdk_encrypted_data_key * encrypted_data_key);
int aws_cryptosdk_mk_kms_encrypt_data_key(struct aws_cryptosdk_mk * mk,
                                          struct aws_cryptosdk_encrypted_data_key * encrypted_data_key,
                                          const struct aws_cryptosdk_data_key * unencrypted_data_key);

int aws_cryptosdk_mk_keystore_destroy(struct aws_cryptosdk_mk * mk);
int aws_cryptosdk_mk_keystore_generate_data_key(struct aws_cryptosdk_mk * mk,
                                                struct aws_cryptosdk_data_key * unencrypted_data_key,
                                                struct aws_cryptosdk_encrypted_data_key * encrypted_data_key);
int aws_cryptosdk_mk_keystore_encrypt_data_key(struct aws_cryptosdk_mk * mk,
                                               struct aws_cryptosdk_encrypted_data_key * encrypted_data_key,
                                               const struct aws_cryptosdk_data_key * unencrypted_data_key);

static struct aws_cryptosdk_mk_vt aws_cryptosdk_mk_vt_list[] = {
    {3,
     aws_cryptosdk_mk_kms_destroy,
     aws_cryptosdk_mk_kms_generate_data_key,
     aws_cryptosdk_mk_kms_encrypt_data_key},
    {3,
     aws_cryptosdk_mk_keystore_destroy,
     aws_cryptosdk_mk_keystore_generate_data_key,
     aws_cryptosdk_mk_keystore_encrypt_data_key}
};

struct aws_cryptosdk_encryption_materials * aws_cryptosdk_encryption_materials_new(struct aws_allocator * alloc, size_t num_keys);

void aws_cryptosdk_encryption_materials_destroy(struct aws_cryptosdk_encryption_materials * enc_mat);

struct aws_cryptosdk_decryption_materials * aws_cryptosdk_decryption_materials_new(struct aws_allocator * alloc);

void aws_cryptosdk_decryption_materials_destroy(struct aws_cryptosdk_decryption_materials * dec_mat);

// TODO: implement and move somewhere else possibly
// should this allocate a key pair struct or write to an existing one?
int generate_trailing_signature_key_pair(struct aws_cryptosdk_key_pair * key_pair, uint16_t alg_id);

int serialize_public_key(struct aws_byte_buf ** output, const struct aws_cryptosdk_public_key * public_key);
int deserialize_public_key(struct aws_cryptosdk_public_key * public_key, const struct aws_byte_buf * input);

#endif // AWS_CRYPTOSDK_MATERIALS_H
