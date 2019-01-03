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
#include <aws/cryptosdk/session.h>

/* Declares AWS strings of type (static const struct aws_string *)
 *
 * This strings will be the key-value pair used in the encryption context.
 */
AWS_STATIC_STRING_FROM_LITERAL(enc_ctx_key, "Example");
AWS_STATIC_STRING_FROM_LITERAL(enc_ctx_value, "String");

int encrypt_string(
    struct aws_allocator *alloc,
    const char *key_arn,
    uint8_t *ciphertext,
    size_t ciphertext_buf_sz,
    size_t *ciphertext_len,
    const uint8_t *plaintext,
    size_t plaintext_len) {
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
    struct aws_hash_table *enc_ctx = aws_cryptosdk_session_get_enc_ctx_ptr_mut(session);
    assert(enc_ctx);

    /* We add the key-value string pair defined at the top of this file to the
     * encryption context.
     */
    int was_created;
    if (AWS_OP_SUCCESS != aws_hash_table_put(enc_ctx, (const void *)enc_ctx_key, (void *)enc_ctx_value, &was_created)) {
        aws_cryptosdk_session_destroy(session);
        return 6;
    }
    assert(was_created == 1);

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

int decrypt_string(
    struct aws_allocator *alloc,
    const char *key_arn,
    uint8_t *plaintext,
    size_t plaintext_buf_sz,
    size_t *plaintext_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len) {
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

    /* The encryption context is stored in plaintext in the ciphertext format, and the
     * AWS Encryption SDK detects it and uses it for decryption, so there is no need to
     * provide it at decrypt time. After decryption is done, you can get a read-only
     * pointer to the encryption context using this function.
     */
    const struct aws_hash_table *enc_ctx = aws_cryptosdk_session_get_enc_ctx_ptr(session);
    assert(enc_ctx);

    /* We retrieve the value associated with our known key. */
    struct aws_hash_element *enc_ctx_kv_pair;
    if (AWS_OP_SUCCESS != aws_hash_table_find(enc_ctx, (const void *)enc_ctx_key, &enc_ctx_kv_pair)) {
        aws_cryptosdk_session_destroy(session);
        return 12;
    }
    assert(enc_ctx_kv_pair);
    const struct aws_string *enc_ctx_value_decrypt = (const struct aws_string *)enc_ctx_kv_pair->value;

    /* We verify that the encryption context value is what we expect. */
    assert(aws_string_eq((const void *)enc_ctx_value, (const void *)enc_ctx_value_decrypt));
    aws_cryptosdk_session_destroy(session);
}

#define BUFFER_SIZE 1024

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s key_arn\n", argv[0]);
        return 1;
    }

    struct aws_allocator *alloc         = aws_default_allocator();
    const char *plaintext_original      = "Hello world!";
    const size_t plaintext_original_len = strlen(plaintext_original);

    uint8_t ciphertext[BUFFER_SIZE];
    uint8_t plaintext_result[BUFFER_SIZE];
    size_t ciphertext_len;
    size_t plaintext_result_len;

    /* Needed so that aws_error_str will work properly. */
    aws_cryptosdk_load_error_strings();

    Aws::SDKOptions options;
    Aws::InitAPI(options);

    int ret = encrypt_string(
        alloc,
        argv[1],
        ciphertext,
        BUFFER_SIZE,
        &ciphertext_len,
        (const uint8_t *)plaintext_original,
        plaintext_original_len);

    if (ret) {
        fprintf(stderr, "Error on encrypt: %s\n", aws_error_str(aws_last_error()));
        Aws::ShutdownAPI(options);
        return ret;
    }
    printf(">> Encrypted to ciphertext of length %zu\n", ciphertext_len);

    ret = decrypt_string(
        alloc, argv[1], plaintext_result, BUFFER_SIZE, &plaintext_result_len, ciphertext, ciphertext_len);

    if (ret) {
        fprintf(stderr, "Error on decrypt: %s\n", aws_error_debug_str(aws_last_error()));
        Aws::ShutdownAPI(options);
        return ret;
    }
    printf(">> Decrypted to plaintext of length %zu\n", plaintext_result_len);

    assert(plaintext_original_len == plaintext_result_len);
    assert(!memcmp(plaintext_original, plaintext_result, plaintext_result_len));
    printf(">> Decrypted plaintext matches original!\n");

    Aws::ShutdownAPI(options);
    return 0;
}
