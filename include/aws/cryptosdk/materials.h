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

/**
 * Abstract types for CMM/MKP/MK: Concrete implementations will create their own structs, which
 * must have the virtual table pointer as the first member, and cast pointers accordingly. See
 * default_cmm.[ch] for an example of this.
 */
struct aws_cryptosdk_cmm;
struct aws_cryptosdk_mkp;
struct aws_cryptosdk_mk;

struct aws_cryptosdk_edk {
    struct aws_byte_buf provider_id;
    struct aws_byte_buf provider_info;
    struct aws_byte_buf enc_data_key;
};

/*
 * TODO: Private key stuff is needed for trailing signature.
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

/**
 * Virtual tables for CMM/MKP/MK. Any implementation should declare a static instance of this,
 * and the first element of the CMM/MKP/MK struct should be a pointer to that static virtual table.
 */
struct aws_cryptosdk_cmm_vt {
    size_t vt_size; // always set to sizeof(struct aws_cryptosdk_cmm_vt)
    char * name; // identifier for debugging purposes only
    void (*destroy)(struct aws_cryptosdk_cmm * cmm);
    int (*generate_encryption_materials)(struct aws_cryptosdk_cmm * cmm,
                                         struct aws_cryptosdk_encryption_materials ** output,
                                         struct aws_cryptosdk_encryption_request * request);
    int (*decrypt_materials)(struct aws_cryptosdk_cmm * cmm,
                             struct aws_cryptosdk_decryption_materials ** output,
                             struct aws_cryptosdk_decryption_request * request);
};

/**
 * VIRTUAL FUNCTION: CMM MUST IMPLEMENT UNLESS IT IS A NO-OP.
 */
static inline void aws_cryptosdk_cmm_destroy(struct aws_cryptosdk_cmm * cmm) {
    VF_CALL_NO_RETURN(destroy, cmm);
}

/**
 * VIRTUAL FUNCTION: CMM MUST IMPLEMENT IF USED FOR ENCRYPTION.
 * Receives encryption request from user and attempts to generate encryption materials, including an encrypted data key
 * and a set of EDKs for doing an encryption.
 * On success returns AWS_OP_SUCCESS and allocates encryption materials object at address pointed to by output.
 * On failure returns AWS_OP_ERR, sets address pointed to by output to NULL, and sets internal AWS error code.
 */
static inline int aws_cryptosdk_cmm_generate_encryption_materials(struct aws_cryptosdk_cmm * cmm,
                                                                  struct aws_cryptosdk_encryption_materials ** output,
                                                                  struct aws_cryptosdk_encryption_request * request) {
    VF_CALL(generate_encryption_materials, cmm, output, request);
}

/**
 * VIRTUAL FUNCTION: CMM MUST IMPLEMENT IF USED FOR DECRYPTION.
 * Receives decryption request from user and attempts to get decryption materials by decrypting an EDK.
 * On success returns AWS_OP_SUCCESS and allocates decryption materials object at address pointed to by output.
 * On failure returns AWS_OP_ERR, sets address pointed to by output to NULL, and sets internal AWS error code.
 */
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

/**
 * VIRTUAL FUNCTION: MKP MUST IMPLEMENT UNLESS IT IS A NO-OP.
 */
static inline void aws_cryptosdk_mkp_destroy(struct aws_cryptosdk_mkp * mkp) {
    VF_CALL_NO_RETURN(destroy, mkp);
}

/**
 * VIRTUAL FUNCTION: MKP MUST IMPLEMENT IF USED FOR ENCRYPTION.
 * The MKP gives a list of all master keys that may be used for encrypting a data key.
 * It may or may not choose to consult the encryption context when deciding what MKs to return.
 * master_keys is an array of *pointers* to struct aws_cryptosdk_mk objects, and it must have
 * already been initialized before this function is called. The MKP should always append the
 * MK pointers to the list.
 *
 * The list of master keys reallocates its own memory on resizing. (See struct aws_array_list
 * implementation.) It does not own the memory of the master keys. It must be cleaned up after
 * it is used, but cleaning up the list does not deallocate any memory associated with the master keys.
 *
 * On success AWS_OP_SUCCESS is returned, and at least one new MK is appended to the list.
 * On failure AWS_OP_ERR is returned, an internal AWS error code is set, and the list is unchanged.
 */
static inline int aws_cryptosdk_mkp_get_master_keys(struct aws_cryptosdk_mkp * mkp,
                                                    struct aws_array_list * master_keys,
                                                    struct aws_hash_table * enc_context) {
    VF_CALL(get_master_keys, mkp, master_keys, enc_context);
}

/**
 * VIRTUAL FUNCTION: MKP MUST IMPLEMENT IF USED FOR DECRYPTION.
 * The MKP attempts to find one of the EDKs to decrypt. edks must be a list of struct aws_cryptosdk_edk
 * instances, not a list of pointers. unencrypted_data_key must point to a byte buffer that is not
 * already initialized to avoid memory leaks.
 *
 * On success AWS_OP_SUCCESS is returned and the byte buffer of the unencrypted data key is allocated
 * and set to the bytes of the data key.
 * On failure AWS_OP_ERR is returned and no memory is allocated. An internal AWS error code is not
 * necessarily set, as failure of this function is considered normal behavior if the MKP cannot
 * decrypt any of the provided EDKs.
 */
static inline int aws_cryptosdk_mkp_decrypt_data_key(struct aws_cryptosdk_mkp * mkp,
                                                     struct aws_byte_buf * unencrypted_data_key,
                                                     const struct aws_array_list * edks,
                                                     struct aws_hash_table * enc_context,
                                                     enum aws_cryptosdk_alg_id alg) {
    VF_CALL(decrypt_data_key, mkp, unencrypted_data_key, edks, enc_context, alg);
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

/**
 * VIRTUAL FUNCTION: MK MUST IMPLEMENT UNLESS IT IS A NO-OP.
 */
static inline void aws_cryptosdk_mk_destroy(struct aws_cryptosdk_mk * mk) {
    VF_CALL_NO_RETURN(destroy, mk);
}

/**
 * VIRTUAL FUNCTION: MK MUST IMPLEMENT IF USED FOR DATA KEY GENERATION. IF IT IS THE ONLY MK
 * AND THIS IS NOT IMPLEMENTED, ENCRYPTION WILL NOT BE POSSIBLE.
 * The MK attempts to generate a new data key, and returns it in both unencrypted and encrypted form.
 * EDK should be uninitialized when this is called to prevent memory leaks.
 * unencrypted_data_key should have already been initialized. (This is handled by
 * aws_cryptosdk_encryption_materials_new.)
 *
 * On success (1) AWS_OP_SUCCESS is returned, (2) the unencrypted data key bytes are written to the byte buffer
 * (which was allocated prior to this call), and (3) the EDK is properly initialized, which means that all byte
 * buffers that are used within it are initialized and have the appropriate data written to them AND that any
 * byte buffers within the EDK that are not used by a particular MK implementation have both their allocator
 * and length set to zero, to ensure both proper clean up and proper serialization.
 *
 * On failure AWS_OP_ERR is returned, an internal AWS error code is set, and no memory is allocated.
 */
static inline int aws_cryptosdk_mk_generate_data_key(struct aws_cryptosdk_mk * mk,
                                                     struct aws_byte_buf * unencrypted_data_key,
                                                     struct aws_cryptosdk_edk * edk,
                                                     struct aws_hash_table * enc_context,
                                                     enum aws_cryptosdk_alg_id alg) {
    VF_CALL(generate_data_key, mk, unencrypted_data_key, edk, enc_context, alg);
}

/**
 * VIRTUAL FUNCTION: MK MUST IMPLEMENT IF USED FOR ENCRYPTION.
 * The MK attempts to encrypt the data key. EDK should be uninitialized when this is called.
 *
 * On success AWS_OP_SUCCESS is returned and the EDK is properly initialized according to the same
 * rules as specified in the comments on aws_cryptosdk_mk_generate_data_key.
 *
 * On failure AWS_OP_ERR is returned, an internal AWS error code is set, and no memory is allocated.
 */
static inline int aws_cryptosdk_mk_encrypt_data_key(struct aws_cryptosdk_mk * mk,
                                                    struct aws_cryptosdk_edk * edk,
                                                    const struct aws_byte_buf * unencrypted_data_key,
                                                    struct aws_hash_table * enc_context,
                                                    enum aws_cryptosdk_alg_id alg) {
    VF_CALL(encrypt_data_key, mk, edk, unencrypted_data_key, enc_context, alg);
}

/**
 * Allocates a new encryption materials object, including allocating the buffer which holds the unencrypted
 * data key and pre-allocates the list of EDKs to the size specified by num_keys. Note that the list of EDKs
 * will be empty and that no memory will be allocated to any byte buffers in that list. They will only be
 * allocated when individual EDKs are generated or encrypted by other calls to the MK. The list will be
 * dynamically allocated and can grow larger. num_keys is simply the limit before a reallocation is needed.
 *
 * On failure, returns NULL and an internal AWS error code is set.
 */
struct aws_cryptosdk_encryption_materials * aws_cryptosdk_encryption_materials_new(struct aws_allocator * alloc,
                                                                                   enum aws_cryptosdk_alg_id alg,
                                                                                   size_t num_keys);

/**
 * Deallocates all memory associated with the encryption materials object including the object itself.
 * All EDKs in the list will have their associated memory also deallocated, but make sure that they have been
 * initialized properly per the comments on aws_cryptosdk_mk_generate_data_key.
 */
void aws_cryptosdk_encryption_materials_destroy(struct aws_cryptosdk_encryption_materials * enc_mat);

/**
 * Allocates a new decryption materials object, including allocating the buffer which holds the unencrypted
 * data key.
 *
 * TODO: Trailing signature key must be implemented, and if any preallocation of memory is needed add it here.
 *
 * On failure, returns NULL and an internal AWS error code is set.
 */
struct aws_cryptosdk_decryption_materials * aws_cryptosdk_decryption_materials_new(struct aws_allocator * alloc,
                                                                                   enum aws_cryptosdk_alg_id alg);

/**
 * Deallocates all memory associated with the decryption materials object including the object itself.
 */
void aws_cryptosdk_decryption_materials_destroy(struct aws_cryptosdk_decryption_materials * dec_mat);


// TODO: implement and move somewhere else possibly
int generate_trailing_signature_key_pair(struct aws_cryptosdk_key_pair * key_pair, enum aws_cryptosdk_alg_id alg);
int serialize_public_key(struct aws_byte_buf ** output, const struct aws_cryptosdk_public_key * public_key);
int deserialize_public_key(struct aws_cryptosdk_public_key * public_key, const struct aws_byte_buf * input);

#endif // AWS_CRYPTOSDK_MATERIALS_H
