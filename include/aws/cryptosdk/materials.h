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
#include <aws/cryptosdk/edk.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/header.h>

/**
 * Abstract types for CMM and KR: Concrete implementations will create their own structs, which
 * must have the virtual table pointer as the first member, and cast pointers accordingly. See
 * default_cmm.[ch] for an example of this.
 */
struct aws_cryptosdk_cmm;
struct aws_cryptosdk_keyring;

/*
 * TODO: Private key stuff is needed for trailing signature.
 */
struct aws_cryptosdk_private_key {
    //FIXME: implement
    int x; // just putting something here for now to avoid warnings
};

struct aws_cryptosdk_public_key {
    //FIXME: implement
    int x; // just putting something here for now to avoid warnings
};

struct aws_cryptosdk_key_pair {
    struct aws_cryptosdk_private_key private_key;
    struct aws_cryptosdk_public_key public_key;
};

/**
 * Input parameters of aws_cryptosdk_cmm_generate_encryption_materials.
 */
struct aws_cryptosdk_encryption_request {
    struct aws_allocator *alloc;
    struct aws_hash_table *enc_context;
    enum aws_cryptosdk_alg_id requested_alg;
    uint64_t plaintext_size;
};

/**
 * Output parameters of aws_cryptosdk_cmm_generate_encryption_materials.
 */
struct aws_cryptosdk_encryption_materials {
    struct aws_allocator *alloc;
    struct aws_byte_buf unencrypted_data_key;
    struct aws_array_list encrypted_data_keys; // list of struct aws_cryptosdk_edk objects
    struct aws_hash_table *enc_context;
    struct aws_cryptosdk_key_pair trailing_signature_key_pair;
    enum aws_cryptosdk_alg_id alg;
};

/**
 * Input parameters of aws_cryptosdk_cmm_decrypt_materials.
 */
struct aws_cryptosdk_decryption_request {
    struct aws_allocator *alloc;
    struct aws_hash_table *enc_context;
    struct aws_array_list encrypted_data_keys;
    enum aws_cryptosdk_alg_id alg;
};

/**
 * Output parameters of aws_cryptosdk_cmm_decrypt_materials.
 */
struct aws_cryptosdk_decryption_materials {
    struct aws_allocator *alloc;
    struct aws_byte_buf unencrypted_data_key;
    struct aws_cryptosdk_public_key trailing_signature_key;
    enum aws_cryptosdk_alg_id alg;
};

/**
 * Input-only parameters of aws_cryptosdk_keyring_on_encrypt.
 */
struct aws_cryptosdk_keyring_on_encrypt_inputs {
    struct aws_hash_table *enc_context;
    enum aws_cryptosdk_alg_id alg;
    uint64_t plaintext_size;
};

/**
 * Output-only parameters of aws_cryptosdk_keyring_on_encrypt.
 *
 * Caller is expected to set edks to point to an already allocated (possibly empty) list.
 * Callee may push new EDKs onto the list, but must not modify EDKs already in the list.
 */
struct aws_cryptosdk_keyring_on_encrypt_outputs {
    struct aws_array_list *edks; // pointer to list of struct aws_cryptosdk_edk objects
    // TODO: add list of metadata strings for which KMS ARNs were used to do encrypt?
};

/**
 * Input-only parameters of aws_cryptosdk_keyring_on_decrypt.
 */
struct aws_cryptosdk_keyring_on_decrypt_inputs {
    struct aws_hash_table *enc_context;
    struct aws_array_list *edks; // pointer to list of struct aws_cryptosdk_edk objects
    enum aws_cryptosdk_alg_id alg;
};

/**
 * Output-only parameters of aws_cryptosdk_keyring_on_decrypt. Always initialize to zero
 * when declaring an object of this type so that the byte buffer is in a proper state.
 */
struct aws_cryptosdk_keyring_on_decrypt_outputs {
    struct aws_byte_buf unencrypted_data_key;
    // TODO: add metadata string for which KMS ARN was used to do decrypt?
};

/*
 * C99 standard dictates that "..." must have at least one argument behind it. Second arg of
 * _VF_CALL macros is always struct type, i.e., "cmm" or "keyring". These helper macros allow
 * us not to make struct_type a named argument, thus handling the case cleanly where there
 * are no more arguments.
 *
 * Note: We work around a VC++ preprocessor bug here. See https://stackoverflow.com/a/4750720
 */
#define AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME(...) AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME_2((__VA_ARGS__, throwaway))
#define AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME_2(args) AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME_3 args
#define AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME_3(struct_type, ...) struct_type

#define AWS_CRYPTOSDK_PRIVATE_VTP_TYPE(...) AWS_CRYPTOSDK_PRIVATE_VTP_TYPE_2((__VA_ARGS__, throwaway))
#define AWS_CRYPTOSDK_PRIVATE_VTP_TYPE_2(args) AWS_CRYPTOSDK_PRIVATE_VTP_TYPE_3 args
#define AWS_CRYPTOSDK_PRIVATE_VTP_TYPE_3(struct_type, ...) const struct aws_cryptosdk_ ## struct_type ## _vt **

/**
 * Macro for virtual function calls that return an integer status value. Checks that vt_size
 * is large enough and that pointer is non-null before attempting call. If checks fail, sets
 * AWS internal error to AWS_ERROR_UNIMPLEMENTED and returns the return value of
 * aws_raise_error(), i.e., AWS_OP_ERR.
 *
 * Note that this depends on a naming convention of always using "cmm" or "keyring" as the
 * name of the pointer variable as the first argument of the virtual function in the inline
 * functions below which call this macro.
 */
#define AWS_CRYPTOSDK_PRIVATE_VF_CALL(fn_name, ...) \
    do { \
        AWS_CRYPTOSDK_PRIVATE_VTP_TYPE(__VA_ARGS__) vtp = \
            (AWS_CRYPTOSDK_PRIVATE_VTP_TYPE(__VA_ARGS__)) AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME(__VA_ARGS__); \
        ptrdiff_t memb_offset = (const uint8_t *)&(*vtp)->fn_name - (const uint8_t *)*vtp; \
        if (memb_offset + sizeof((*vtp)->fn_name) > (*vtp)->vt_size || !(*vtp)->fn_name) { \
            return aws_raise_error(AWS_ERROR_UNIMPLEMENTED); \
        } \
        return (*vtp)->fn_name(__VA_ARGS__); \
    } while (0)

/**
 * Macro for virtual function calls with no return value, e.g. destroy. Checks that vt_size is
 * large enough and that pointer is non-null before attempting call. If checks fail, sets error
 * code to AWS_ERROR_UNIMPLEMENTED and otherwise is a no-op.
 */
#define AWS_CRYPTOSDK_PRIVATE_VF_CALL_NO_RETURN(fn_name, ...) \
    do { \
        AWS_CRYPTOSDK_PRIVATE_VTP_TYPE(__VA_ARGS__) vtp = \
            (AWS_CRYPTOSDK_PRIVATE_VTP_TYPE(__VA_ARGS__)) AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME(__VA_ARGS__); \
        ptrdiff_t memb_offset = (const uint8_t *)&(*vtp)->fn_name - (const uint8_t *)*vtp; \
        if (memb_offset + sizeof((*vtp)->fn_name) > (*vtp)->vt_size || !(*vtp)->fn_name) { \
            aws_raise_error(AWS_ERROR_UNIMPLEMENTED); \
        } else { \
            (*vtp)->fn_name(__VA_ARGS__); \
        } \
    } while (0)

/**
 * Virtual tables for CMM and keyring. Any implementation should declare a static instance of
 * this, and the first element of the CMM or keyring struct should be a pointer to that static
 * virtual table.
 */
struct aws_cryptosdk_cmm_vt {
    /**
     * Always set to sizeof(struct aws_cryptosdk_cmm_vt).
     */
    size_t vt_size;
    /**
     * Identifier for debugging purposes only.
     */
    const char * name;
    /**
     * VIRTUAL FUNCTION: must implement unless it is a no-op. It is better to implement it as
     * a no-op function to avoid setting error code.
     */
    void (*destroy)(struct aws_cryptosdk_cmm * cmm);

    /**
     * VIRTUAL FUNCTION: must implement if used for encryption.
     */
    int (*generate_encryption_materials)(struct aws_cryptosdk_cmm * cmm,
                                         struct aws_cryptosdk_encryption_materials ** output,
                                         struct aws_cryptosdk_encryption_request * request);
    /**
     * VIRTUAL FUNCTION: must implement if used for decryption.
     */
    int (*decrypt_materials)(struct aws_cryptosdk_cmm * cmm,
                             struct aws_cryptosdk_decryption_materials ** output,
                             struct aws_cryptosdk_decryption_request * request);
};

static inline void aws_cryptosdk_cmm_destroy(struct aws_cryptosdk_cmm * cmm) {
    if (cmm) AWS_CRYPTOSDK_PRIVATE_VF_CALL_NO_RETURN(destroy, cmm);
}

/**
 * Receives encryption request from user and attempts to generate encryption materials,
 * including an encrypted data key and a set of EDKs for doing an encryption.
 *
 * On success returns AWS_OP_SUCCESS and allocates encryption materials object at address
 * pointed to by output.
 *
 * On failure returns AWS_OP_ERR, sets address pointed to by output to NULL, and sets
 * internal AWS error code.
 */
static inline int aws_cryptosdk_cmm_generate_encryption_materials(
    struct aws_cryptosdk_cmm * cmm,
    struct aws_cryptosdk_encryption_materials ** output,
    struct aws_cryptosdk_encryption_request * request) {
    AWS_CRYPTOSDK_PRIVATE_VF_CALL(generate_encryption_materials, cmm, output, request);
}

/**
 * Receives decryption request from user and attempts to get decryption materials by
 * decrypting an EDK.
 *
 * On success returns AWS_OP_SUCCESS and allocates decryption materials object at address
 * pointed to by output.
 *
 * On failure returns AWS_OP_ERR, sets address pointed to by output to NULL, and sets
 * internal AWS error code.
 */
static inline int aws_cryptosdk_cmm_decrypt_materials(
    struct aws_cryptosdk_cmm * cmm,
    struct aws_cryptosdk_decryption_materials ** output,
    struct aws_cryptosdk_decryption_request * request) {
    AWS_CRYPTOSDK_PRIVATE_VF_CALL(decrypt_materials, cmm, output, request);
}

struct aws_cryptosdk_keyring_vt {
    /**
     * Always set to sizeof(struct aws_cryptosdk_keyring_vt).
     */
    size_t vt_size;
    /**
     * Identifier for debugging purposes only.
     */
    const char * name;
    /**
     * VIRTUAL FUNCTION: must implement unless it is a no-op. It is better to implement it as
     * a no-op function to avoid setting error code.
     */
    void (*destroy)(struct aws_cryptosdk_keyring * keyring);

    /**
     * VIRTUAL FUNCTION: must implement if used for encryption.
     *
     * When the buffer for the unencrypted data key in the result object is not NULL at the
     * time of the call, it must not be changed by callee. When the buffer of the unencrypted
     * data key is NULL at the time of the call and the call returns successfully, the callee
     * must have set the buffer. All buffers for any EDKs pushed onto the list must be in a
     * valid state, which means either that they are set to all zeroes or that they have been
     * initialized using one of the byte buffer initialization functions. This assures proper
     * clean up and serialization.
     */
    int (*on_encrypt)(struct aws_cryptosdk_keyring *keyring,
                      struct aws_cryptosdk_keyring_on_encrypt_outputs *outputs,
                      struct aws_byte_buf *unencrypted_data_key,
                      const struct aws_cryptosdk_keyring_on_encrypt_inputs *inputs);

    /**
     * VIRTUAL FUNCTION: must implement if used for decryption.
     *
     * Implementations must properly initialize the unencrypted data key buffer when an
     * EDK is decrypted and leave the unencrypted data key buffer pointer set to NULL
     * when no EDK is decrypted.
     */
    int (*on_decrypt)(struct aws_cryptosdk_keyring *keyring,
                      struct aws_cryptosdk_keyring_on_decrypt_outputs *outputs,
                      const struct aws_cryptosdk_keyring_on_decrypt_inputs *inputs);
};

static inline void aws_cryptosdk_keyring_destroy(struct aws_cryptosdk_keyring *keyring) {
    if (keyring) AWS_CRYPTOSDK_PRIVATE_VF_CALL_NO_RETURN(destroy, keyring);
}

/**
 * If byte buffer for unencrypted_data_key is already allocated, this makes zero or more
 * encrypted data keys which decrypt to that data key and pushes them onto the EDK list.
 *
 * If byte buffer for unencrypted_data_key is not already allocated, this makes a new
 * data key, allocates the buffer, and puts the data key into that buffer. It also makes
 * zero or more encrypted data keys which decrypt to that data key and pushes them onto
 * the EDK list.
 *
 * On success (1) AWS_OP_SUCCESS is returned, (2) if the unencrypted_data_key buffer was
 * previously allocated, it will be unchanged, (3) if the unencrypted_data_key buffer was
 * not previously allocated, it will now be allocated, (4) zero or more EDKS will be
 * appended to the list of EDKS.
 *
 * On failure AWS_OP_ERR is returned, an error code is set, and no memory is allocated.
 */
static inline int aws_cryptosdk_keyring_on_encrypt(
    struct aws_cryptosdk_keyring *keyring,
    struct aws_cryptosdk_keyring_on_encrypt_outputs *outputs,
    struct aws_byte_buf *unencrypted_data_key,
    const struct aws_cryptosdk_keyring_on_encrypt_inputs *inputs) {
    if (!unencrypted_data_key->buffer && aws_array_list_length(outputs->edks)) {
        /* If a data key has not already been generated, there should be no EDKs.
         * Generating a new one and then pushing new EDKs on the list would cause the
         * list of EDKs to be inconsistent. (i.e., they would decrypt to different data
         * keys.) We should never get into this state, so exit with an error.
         */
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    }
    AWS_CRYPTOSDK_PRIVATE_VF_CALL(on_encrypt,
                                  keyring,
                                  outputs,
                                  unencrypted_data_key,
                                  inputs);
}

/**
 * The keyring attempts to find one of the EDKs to decrypt. The unencrypted data key
 * buffer object should be zeroed when this is called.
 *
 * On success AWS_OP_SUCCESS will be returned. This does not necessarily mean that the
 * data key will be decrypted, as it is normal behavior that a keyring may not
 * find an EDK that it can decrypt. To determine whether the data key was decrypted,
 * check result->unencrypted_data_key.buffer. If the data key was not decrypted, that
 * pointer will be set to NULL. If the data key was decrypted, that pointer will point
 * to the raw bytes of the key.
 *
 * On failure, AWS_OP_ERR is returned, an error code is set, and no memory is allocated.
 * Failure here refers to an unexpected error in the operation of the keyring, rather
 * than an inability to decrypt any of the EDKs.
 */
static inline int aws_cryptosdk_keyring_on_decrypt(
    struct aws_cryptosdk_keyring *keyring,
    struct aws_cryptosdk_keyring_on_decrypt_outputs *outputs,
    const struct aws_cryptosdk_keyring_on_decrypt_inputs *inputs) {
    if (outputs->unencrypted_data_key.buffer) return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    AWS_CRYPTOSDK_PRIVATE_VF_CALL(on_decrypt, keyring, outputs, inputs);
}

/**
 * Allocates a new encryption materials object, including allocating memory to the list
 * of EDKs. The list of EDKs will be empty and no memory will be allocated to any byte
 * buffers in that list, nor will memory be allocated to the unencrypted data key buffer.
 * They will only be allocated when individual keys are generated or encrypted by other
 * calls to the KR.
 *
 * On failure, returns NULL and an error code will be set.
 */
struct aws_cryptosdk_encryption_materials * aws_cryptosdk_encryption_materials_new(
    struct aws_allocator * alloc,
    enum aws_cryptosdk_alg_id alg);

/**
 * Deallocates all memory associated with the encryption materials object including the
 * object itself. All keys in the materials will have their associated memory also
 * deallocated, but make sure that they have been initialized properly per the comments
 * on aws_cryptosdk_keyring_generate_data_key.
 */
void aws_cryptosdk_encryption_materials_destroy(struct aws_cryptosdk_encryption_materials * enc_mat);

/**
 * Allocates a new decryption materials object. Note that no memory will be allocated to
 * the byte buffer for  the unencrypted data key. That will only be allocated when an EDK
 * is decrypted.
 *
 * TODO: Trailing signature key must be implemented, and if any preallocation of memory
 * is needed add it here.
 *
 * On failure, returns NULL and an internal AWS error code is set.
 */
struct aws_cryptosdk_decryption_materials * aws_cryptosdk_decryption_materials_new(
    struct aws_allocator * alloc,
    enum aws_cryptosdk_alg_id alg);

/**
 * Deallocates all memory associated with the decryption materials object including the
 * object itself and the unencrypted data key it is holding, if an EDK has been decrypted
 * successfully.
 */
void aws_cryptosdk_decryption_materials_destroy(struct aws_cryptosdk_decryption_materials * dec_mat);

#endif // AWS_CRYPTOSDK_MATERIALS_H
