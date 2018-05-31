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
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/header.h>

/* Opaque type: first element is a struct aws_cryptosdk_mk_vt */
struct aws_cryptosdk_mk;

/* Opaque type: first element is a struct aws_cryptosdk_mkp_vt */
struct aws_cryptosdk_mkp;

/* Opaque type: first element is a struct aws_cryptosdk_cmm_vt */
struct aws_cryptosdk_cmm;

struct aws_cryptosdk_edk {
    struct aws_byte_buf provider_id;
    struct aws_byte_buf provider_info;
    struct aws_byte_buf enc_data_key;
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

struct aws_cryptosdk_encryption_request {
    struct aws_allocator * alloc;
    struct aws_hash_table * enc_context;
    enum aws_cryptosdk_alg_id requested_alg;
    uint64_t plaintext_size;
};

struct aws_cryptosdk_encryption_materials {
    struct aws_allocator * alloc;
    struct aws_byte_buf unencrypted_data_key;
    struct aws_array_list encrypted_data_keys; // list of struct aws_cryptosdk_edk objects
    struct aws_hash_table * enc_context;
    struct aws_cryptosdk_key_pair trailing_signature_key_pair;
    enum aws_cryptosdk_alg_id alg;
};

struct aws_cryptosdk_decryption_request {
    struct aws_allocator * alloc;
    struct aws_hash_table * enc_context;
    struct aws_array_list encrypted_data_keys;
    enum aws_cryptosdk_alg_id alg;
};

struct aws_cryptosdk_decryption_materials {
    struct aws_allocator * alloc;
    struct aws_byte_buf unencrypted_data_key;
    struct aws_cryptosdk_public_key trailing_signature_key;
};

/* Opaque type: first element is a struct aws_cryptosdk_cmm_vt */
struct aws_cryptosdk_cmm;

/* Opaque type: first element is a struct aws_cryptosdk_mkp_vt */
struct aws_cryptosdk_mkp;

/* Opaque type: first element is a struct aws_cryptosdk_mk_vt */
struct aws_cryptosdk_mk;

struct aws_cryptosdk_cmm_vt {
    size_t vt_size;
    char * name;
    void (*destroy)(struct aws_cryptosdk_cmm * cmm);
    int (*generate_encryption_materials)(struct aws_cryptosdk_cmm * cmm,
                                         struct aws_cryptosdk_encryption_materials ** output,
                                         struct aws_cryptosdk_encryption_request * request);
    int (*decrypt_materials)(struct aws_cryptosdk_cmm * cmm,
                             struct aws_cryptosdk_decryption_materials ** output,
                             struct aws_cryptosdk_decryption_request * request);
};

/**
 * Macro for virtual function calls that return an integer error code. Checks that vt_size is large enough and that pointer is
 * non-null before attempting call. If checks fail, sets AWS internal error to AWS_CRYPTOSDK_ERR_VIRTUAL_FUNCTION_UNIMPLEMENTED
 * and returns the return value of aws_raise_error(), i.e., AWS_OP_ERR.
 */
#define VF_CALL(fn_name, struct_type, ...) \
    do { \
        const struct aws_cryptosdk_ ## struct_type ## _vt ** vtp = (const struct aws_cryptosdk_ ## struct_type ## _vt **) struct_type; \
        ptrdiff_t memb_offset = (const uint8_t *)&(*vtp)->fn_name - (const uint8_t *)*vtp; \
        if (memb_offset + sizeof((*vtp)->fn_name) > (*vtp)->vt_size || !(*vtp)->fn_name) { \
            return aws_raise_error(AWS_CRYPTOSDK_ERR_VIRTUAL_FUNCTION_UNIMPLEMENTED); \
        } \
        return (*vtp)->fn_name(struct_type, ##__VA_ARGS__); \
    } while (0)

/**
 * Macro for virtual function calls with no return value, e.g. destroy. Checks that vt_size is large enough and that pointer is
 * non-null before attempting call. If checks fail, sets AWS internal error to AWS_CRYPTOSDK_ERR_VIRTUAL_FUNCTION_UNIMPLEMENTED
 * and otherwise is a no-op.
 */
#define VF_CALL_NO_RETURN(fn_name, struct_type, ...) \
    do { \
        const struct aws_cryptosdk_ ## struct_type ## _vt ** vtp = (const struct aws_cryptosdk_ ## struct_type ## _vt **) struct_type; \
        ptrdiff_t memb_offset = (const uint8_t *)&(*vtp)->fn_name - (const uint8_t *)*vtp; \
        if (memb_offset + sizeof((*vtp)->fn_name) > (*vtp)->vt_size || !(*vtp)->fn_name) { \
            aws_raise_error(AWS_CRYPTOSDK_ERR_VIRTUAL_FUNCTION_UNIMPLEMENTED); \
        } else { \
            (*vtp)->fn_name(struct_type, ##__VA_ARGS__); \
        } \
    } while (0)

static inline void aws_cryptosdk_cmm_destroy(struct aws_cryptosdk_cmm * cmm) {
    VF_CALL_NO_RETURN(destroy, cmm);
}

static inline int aws_cryptosdk_cmm_generate_encryption_materials(struct aws_cryptosdk_cmm * cmm,
                                                                  struct aws_cryptosdk_encryption_materials ** output,
                                                                  struct aws_cryptosdk_encryption_request * request) {
    VF_CALL(generate_encryption_materials, cmm, output, request);
}

static inline int aws_cryptosdk_cmm_decrypt_materials(struct aws_cryptosdk_cmm * cmm,
                                                      struct aws_cryptosdk_decryption_materials ** output,
                                                      struct aws_cryptosdk_decryption_request * request) {
    VF_CALL(decrypt_materials, cmm, output, request);
}

struct aws_cryptosdk_mkp_vt {
    size_t vt_size;
    char * name;
    void (*destroy)(struct aws_cryptosdk_mkp * mkp);
    int (*get_master_keys)(struct aws_cryptosdk_mkp * mkp,
                              struct aws_array_list * master_keys, // list of (aws_cryptosdk_mk *)
                              struct aws_hash_table * enc_context);
    int (*decrypt_data_key)(struct aws_cryptosdk_mkp * mkp,
                            struct aws_byte_buf * unencrypted_data_key,
                            const struct aws_array_list * encrypted_data_keys,
                            struct aws_hash_table * enc_context,
                            enum aws_cryptosdk_alg_id alg);
};

static inline void aws_cryptosdk_mkp_destroy(struct aws_cryptosdk_mkp * mkp) {
    VF_CALL_NO_RETURN(destroy, mkp);
}

static inline int aws_cryptosdk_mkp_get_master_keys(struct aws_cryptosdk_mkp * mkp,
                                                       struct aws_array_list * master_keys,
                                                       struct aws_hash_table * enc_context) {
    VF_CALL(get_master_keys, mkp, master_keys, enc_context);
}

static inline int aws_cryptosdk_mkp_decrypt_data_key(struct aws_cryptosdk_mkp * mkp,
                                                     struct aws_byte_buf * unencrypted_data_key,
                                                     const struct aws_array_list * encrypted_data_keys,
                                                     struct aws_hash_table * enc_context,
                                                     enum aws_cryptosdk_alg_id alg) {
    VF_CALL(decrypt_data_key, mkp, unencrypted_data_key, encrypted_data_keys, enc_context, alg);
}

struct aws_cryptosdk_mk_vt {
    size_t vt_size;
    char * name;
    void (*destroy)(struct aws_cryptosdk_mk * mk);
    int (*generate_data_key)(struct aws_cryptosdk_mk * mk,
                             struct aws_byte_buf * unencrypted_data_key,
                             struct aws_cryptosdk_edk * encrypted_data_key,
                             struct aws_hash_table * enc_context,
                             enum aws_cryptosdk_alg_id alg);
    int (*encrypt_data_key)(struct aws_cryptosdk_mk * mk,
                            struct aws_cryptosdk_edk * encrypted_data_key,
                            const struct aws_byte_buf * unencrypted_data_key,
                            struct aws_hash_table * enc_context,
                            enum aws_cryptosdk_alg_id alg);
};

static inline void aws_cryptosdk_mk_destroy(struct aws_cryptosdk_mk * mk) {
    VF_CALL_NO_RETURN(destroy, mk);
}

static inline int aws_cryptosdk_mk_generate_data_key(struct aws_cryptosdk_mk * mk,
                                                     struct aws_byte_buf * unencrypted_data_key,
                                                     struct aws_cryptosdk_edk * encrypted_data_key,
                                                     struct aws_hash_table * enc_context,
                                                     enum aws_cryptosdk_alg_id alg) {
    VF_CALL(generate_data_key, mk, unencrypted_data_key, encrypted_data_key, enc_context, alg);
}

static inline int aws_cryptosdk_mk_encrypt_data_key(struct aws_cryptosdk_mk * mk,
                                                    struct aws_cryptosdk_edk * encrypted_data_key,
                                                    const struct aws_byte_buf * unencrypted_data_key,
                                                    struct aws_hash_table * enc_context,
                                                    enum aws_cryptosdk_alg_id alg) {
    VF_CALL(encrypt_data_key, mk, encrypted_data_key, unencrypted_data_key, enc_context, alg);
}

struct aws_cryptosdk_encryption_materials * aws_cryptosdk_encryption_materials_new(struct aws_allocator * alloc,
                                                                                   enum aws_cryptosdk_alg_id alg,
                                                                                   size_t num_keys);

void aws_cryptosdk_encryption_materials_destroy(struct aws_cryptosdk_encryption_materials * enc_mat);

struct aws_cryptosdk_decryption_materials * aws_cryptosdk_decryption_materials_new(struct aws_allocator * alloc,
                                                                                   enum aws_cryptosdk_alg_id alg);

void aws_cryptosdk_decryption_materials_destroy(struct aws_cryptosdk_decryption_materials * dec_mat);


// TODO: implement and move somewhere else possibly
int generate_trailing_signature_key_pair(struct aws_cryptosdk_key_pair * key_pair, enum aws_cryptosdk_alg_id alg);
int serialize_public_key(struct aws_byte_buf ** output, const struct aws_cryptosdk_public_key * public_key);
int deserialize_public_key(struct aws_cryptosdk_public_key * public_key, const struct aws_byte_buf * input);

#endif // AWS_CRYPTOSDK_MATERIALS_H
