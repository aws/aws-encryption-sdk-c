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

#include <aws/cryptosdk/cpp/kms_keyring.h>
#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/enc_ctx.h>
#include <aws/cryptosdk/session.h>

int encrypt_string(
    struct aws_allocator *alloc,
    const char *key_arn,
    uint8_t *ciphertext,
    size_t ciphertext_buf_sz,
    size_t *ciphertext_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    struct aws_hash_table *my_enc_ctx) {
    struct aws_cryptosdk_keyring *kms_keyring = Aws::Cryptosdk::KmsKeyring::Builder().Build({ key_arn });
    if (!kms_keyring) {
        fprintf(stderr, "Failed to build KMS Keyring. Did you specify a valid KMS CMK ARN?\n");
        return 2;
    }

    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_default_cmm_new(alloc, kms_keyring);
    if (!cmm) {
        /* Any new function can return NULL on a memory allocation failure.
         * We give up on those.
         */
        aws_cryptosdk_keyring_release(kms_keyring);
        return 3;
    }

    /* The CMM has a reference to the keyring now. We release our reference so that
     * the keyring will be destroyed when the CMM is.
     */
    aws_cryptosdk_keyring_release(kms_keyring);

    struct aws_cryptosdk_session *session = aws_cryptosdk_session_new_from_cmm(alloc, AWS_CRYPTOSDK_ENCRYPT, cmm);
    if (!session) {
        aws_cryptosdk_cmm_release(cmm);
        return 4;
    }

    /* The session has a reference to the CMM now. We release our reference so that
     * when the CMM (and the keyring) will be destroyed when the session is.
     */
    aws_cryptosdk_cmm_release(cmm);

    if (AWS_OP_SUCCESS != aws_cryptosdk_session_set_message_size(session, plaintext_len)) {
        aws_cryptosdk_session_destroy(session);
        return 5;
    }

    /* The encryption context is an AWS hash table where both the key and value
     * types are AWS strings. Both AWS hash tables and AWS strings are defined in
     * the aws-c-common library.
     *
     * This function gives us a mutable pointer to the encryption context, allowing
     * us to add or modify items. It only works for encrypt sessions and only
     * before aws_cryptosdk_session_process is called. At other times, it returns NULL.
     */
    struct aws_hash_table *session_enc_ctx = aws_cryptosdk_session_get_enc_ctx_ptr_mut(session);
    assert(session_enc_ctx);

    /* We copy the contents of our own encryption context into the session's. */
    if (AWS_OP_SUCCESS != aws_cryptosdk_enc_ctx_clone(alloc, session_enc_ctx, my_enc_ctx)) {
        aws_cryptosdk_session_destroy(session);
        return 6;
    }

    /* We encrypt the data. */
    size_t plaintext_consumed;
    if (AWS_OP_SUCCESS !=
        aws_cryptosdk_session_process(
            session, ciphertext, ciphertext_buf_sz, ciphertext_len, plaintext, plaintext_len, &plaintext_consumed)) {
        aws_cryptosdk_session_destroy(session);
        return 7;
    }

    assert(aws_cryptosdk_session_is_done(session));
    assert(plaintext_consumed == plaintext_len);

    /* This call deallocates all of the memory allocated in this function, including
     * the keyring and CMM, since we already released their pointers.
     */
    aws_cryptosdk_session_destroy(session);
    return 0;
}

int decrypt_string_and_verify_encryption_context(
    struct aws_allocator *alloc,
    const char *key_arn,
    uint8_t *plaintext,
    size_t plaintext_buf_sz,
    size_t *plaintext_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    struct aws_hash_table *my_enc_ctx) {
    struct aws_cryptosdk_keyring *kms_keyring = Aws::Cryptosdk::KmsKeyring::Builder().Build({ key_arn });
    if (!kms_keyring) {
        fprintf(stderr, "Failed to build KMS Keyring. Did you specify a valid KMS CMK ARN?\n");
        return 8;
    }

    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_default_cmm_new(alloc, kms_keyring);
    if (!cmm) {
        aws_cryptosdk_keyring_release(kms_keyring);
        return 9;
    }

    aws_cryptosdk_keyring_release(kms_keyring);

    struct aws_cryptosdk_session *session = aws_cryptosdk_session_new_from_cmm(alloc, AWS_CRYPTOSDK_DECRYPT, cmm);
    if (!session) {
        aws_cryptosdk_cmm_release(cmm);
        return 10;
    }

    aws_cryptosdk_cmm_release(cmm);

    size_t ciphertext_consumed;
    if (AWS_OP_SUCCESS !=
        aws_cryptosdk_session_process(
            session, plaintext, plaintext_buf_sz, plaintext_len, ciphertext, ciphertext_len, &ciphertext_consumed)) {
        aws_cryptosdk_session_destroy(session);
        return 11;
    }

    assert(aws_cryptosdk_session_is_done(session));
    assert(ciphertext_consumed == ciphertext_len);

    /* The encryption context is stored in plaintext in the encrypted message, and the
     * AWS Encryption SDK detects it and uses it for decryption, so there is no need to
     * provide it at decrypt time. After decryption is done, use this function to get a
     * read-only pointer to the encryption context.
     */
    const struct aws_hash_table *session_enc_ctx = aws_cryptosdk_session_get_enc_ctx_ptr(session);
    assert(session_enc_ctx);

    /* Because the CMM can add new entries to the encryption context, we do not
     * require that the encryption context matches, but only that the entries we
     * put in are there.
     */
    for (struct aws_hash_iter iter = aws_hash_iter_begin(my_enc_ctx); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {
        struct aws_hash_element *session_enc_ctx_kv_pair;
        if (AWS_OP_SUCCESS != aws_hash_table_find(session_enc_ctx, iter.element.key, &session_enc_ctx_kv_pair)) {
            aws_cryptosdk_session_destroy(session);
            return 12;
        }

        if (!session_enc_ctx_kv_pair ||
            !aws_string_eq(
                (struct aws_string *)iter.element.value, (struct aws_string *)session_enc_ctx_kv_pair->value)) {
            fprintf(stderr, "Wrong encryption context!\n");
            abort();
        }
    }

    aws_cryptosdk_session_destroy(session);
    return 0;
}

/* Allocates a hash table for holding the encryption context and puts a few sample values in it. */
int set_up_enc_ctx(struct aws_allocator *alloc, struct aws_hash_table *enc_ctx) {
    if (AWS_OP_SUCCESS != aws_cryptosdk_enc_ctx_init(alloc, enc_ctx)) return 12;

    /* Declares AWS strings of type (static const struct aws_string *)
     *
     * These strings will be the key-value pair used in the encryption context.
     * For more information on the encryption context, see
     * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
     */
    AWS_STATIC_STRING_FROM_LITERAL(enc_ctx_key1, "Example");
    AWS_STATIC_STRING_FROM_LITERAL(enc_ctx_value1, "String");
    AWS_STATIC_STRING_FROM_LITERAL(enc_ctx_key2, "Company");
    AWS_STATIC_STRING_FROM_LITERAL(enc_ctx_value2, "MyCryptoCorp");

    int was_created;
    if (AWS_OP_SUCCESS != aws_hash_table_put(enc_ctx, enc_ctx_key1, (void *)enc_ctx_value1, &was_created)) {
        aws_cryptosdk_enc_ctx_clean_up(enc_ctx);
        return 13;
    }
    assert(was_created == 1);
    if (AWS_OP_SUCCESS != aws_hash_table_put(enc_ctx, enc_ctx_key2, (void *)enc_ctx_value2, &was_created)) {
        aws_cryptosdk_enc_ctx_clean_up(enc_ctx);
        return 14;
    }
    assert(was_created == 1);
    return 0;
}

#define BUFFER_SIZE 1024

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s key_arn\n", argv[0]);
        return 1;
    }

    /* Needed so that aws_error_str will work properly. */
    aws_cryptosdk_load_error_strings();

    struct aws_allocator *alloc = aws_default_allocator();

    struct aws_hash_table enc_ctx;
    int ret = set_up_enc_ctx(alloc, &enc_ctx);
    if (ret) {
        fprintf(stderr, "Error on encryption context setup: %s\n", aws_error_str(aws_last_error()));
        return ret;
    }

    /* We need to intialize the AWS SDK for C++ when we use the C++ KMS keyring. */
    Aws::SDKOptions options;
    Aws::InitAPI(options);

    const char *plaintext_original      = "Hello world!";
    const size_t plaintext_original_len = strlen(plaintext_original);

    uint8_t ciphertext[BUFFER_SIZE];
    uint8_t plaintext_result[BUFFER_SIZE];
    size_t ciphertext_len;
    size_t plaintext_result_len;

    ret = encrypt_string(
        alloc,
        argv[1],
        ciphertext,
        BUFFER_SIZE,
        &ciphertext_len,
        (const uint8_t *)plaintext_original,
        plaintext_original_len,
        &enc_ctx);

    if (ret) {
        fprintf(stderr, "Error on encrypt: %s\n", aws_error_str(aws_last_error()));
        goto done;
    }
    printf(">> Encrypted to ciphertext of length %zu\n", ciphertext_len);

    ret = decrypt_string_and_verify_encryption_context(
        alloc, argv[1], plaintext_result, BUFFER_SIZE, &plaintext_result_len, ciphertext, ciphertext_len, &enc_ctx);

    if (ret) {
        fprintf(stderr, "Error on decrypt: %s\n", aws_error_str(aws_last_error()));
        goto done;
    }
    printf(">> Decrypted to plaintext of length %zu\n", plaintext_result_len);

    assert(plaintext_original_len == plaintext_result_len);
    assert(!memcmp(plaintext_original, plaintext_result, plaintext_result_len));
    printf(">> Decrypted plaintext matches original!\n");

done:
    Aws::ShutdownAPI(options);
    aws_cryptosdk_enc_ctx_clean_up(&enc_ctx);
    return ret;
}
