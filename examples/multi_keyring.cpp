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

#include <aws/common/string.h>
#include <aws/cryptosdk/cpp/kms_keyring.h>
#include <aws/cryptosdk/multi_keyring.h>
#include <aws/cryptosdk/raw_aes_keyring.h>
#include <aws/cryptosdk/session.h>

/* Encrypts/decrypts the entire input buffer using the keyring provided. */
void encrypt_or_decrypt(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_keyring *keyring,
    enum aws_cryptosdk_mode mode,
    uint8_t *output,
    size_t output_buf_sz,
    size_t *output_len,
    const uint8_t *input,
    size_t input_len) {
    struct aws_cryptosdk_session *session = aws_cryptosdk_session_new_from_keyring(alloc, mode, keyring);
    if (!session) abort();

    if (mode == AWS_CRYPTOSDK_ENCRYPT) {
        if (AWS_OP_SUCCESS != aws_cryptosdk_session_set_message_size(session, input_len)) abort();
    }

    size_t input_consumed;
    if (AWS_OP_SUCCESS !=
        aws_cryptosdk_session_process(session, output, output_buf_sz, output_len, input, input_len, &input_consumed))
        abort();
    if (!aws_cryptosdk_session_is_done(session)) abort();
    if (input_consumed != input_len) abort();

    /* This destroys the session but not the keyring, since the keyring pointer was not released. */
    aws_cryptosdk_session_destroy(session);
}

#define BUFFER_SIZE 1024

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s key_arn aes_256_key_file\n", argv[0]);
        return 1;
    }

    Aws::SDKOptions options;
    Aws::InitAPI(options);
    /* We will create two different keyrings and link them together with a multi-keyring.
     * The first is a KMS keyring, the same as used in the string and file examples.
     */
    struct aws_cryptosdk_keyring *kms_keyring = Aws::Cryptosdk::KmsKeyring::Builder().Build(argv[1]);
    if (!kms_keyring) {
        fprintf(stderr, "KMS keyring not created. Did you provide a valid KMS CMK ARN?\n");
        return 2;
    }

    struct aws_allocator *alloc = aws_default_allocator();

    /* The second keyring is a raw AES keyring that will hold an escrow key.
     * See the AES keyring example for more explanation of the creation of this keyring.
     */
    FILE *key_file = fopen(argv[2], "rb");
    if (!key_file) abort();
    uint8_t wrapping_key[32];
    size_t wrapping_key_len = fread(wrapping_key, 1, 32, key_file);
    uint8_t throwaway;
    fread(&throwaway, 1, 1, key_file);
    if (!feof(key_file) || !(wrapping_key_len == AWS_CRYPTOSDK_AES256)) {
        fclose(key_file);
        fprintf(stderr, "Key file must be 256 bits only.\n");
        aws_secure_zero(wrapping_key, wrapping_key_len);
        aws_cryptosdk_keyring_release(kms_keyring);
        return 3;
    }
    fclose(key_file);

    AWS_STATIC_STRING_FROM_LITERAL(wrapping_key_namespace, "my master keys");
    AWS_STATIC_STRING_FROM_LITERAL(wrapping_key_name, "escrow key #1");
    struct aws_cryptosdk_keyring *escrow_keyring = aws_cryptosdk_raw_aes_keyring_new(
        alloc, wrapping_key_namespace, wrapping_key_name, wrapping_key, AWS_CRYPTOSDK_AES256);
    if (!escrow_keyring) abort();
    /* Zero out our copy of the escrow key now that it is stored in the keyring. */
    aws_secure_zero(wrapping_key, wrapping_key_len);

    /* We create a multi-keyring. The first keyring specified on creation is the
     * generator keyring. This will be the first keyring called on encryption
     * attempts with the multi-keyring, and it is expected to do the data key
     * generation. Alternatively, you can create a multi-keyring without a
     * generator by passing in NULL as the second argument, but you will only
     * be able to use it for decryption.
     */
    struct aws_cryptosdk_keyring *multi_keyring = aws_cryptosdk_multi_keyring_new(alloc, kms_keyring);
    if (!multi_keyring) abort();

    /* We add the escrow keyring as a child keyring to the multi-keyring.
     * Any data encrypted with the multi-keyring will be decryptable by
     * either the KMS keyring or by the escrow keyring.
     */
    if (AWS_OP_SUCCESS != aws_cryptosdk_multi_keyring_add_child(multi_keyring, escrow_keyring)) abort();
    /*
     * The multi-keyring holds references to the other two keyrings, so we
     * could release the other two keyring pointers and allow them to be
     * destroyed upon the destruction of the multi-keyring if we wanted.
     * However, we will use the other two keyrings individually in the
     * decryption step, so we will not do that here.
     */

    const char *plaintext_original      = "Hello world!";
    const size_t plaintext_original_len = strlen(plaintext_original);

    uint8_t ciphertext[BUFFER_SIZE];
    size_t ciphertext_len;

    encrypt_or_decrypt(
        alloc,
        multi_keyring,
        AWS_CRYPTOSDK_ENCRYPT,
        ciphertext,
        BUFFER_SIZE,
        &ciphertext_len,
        (const uint8_t *)plaintext_original,
        plaintext_original_len);
    printf(">> Encrypted to ciphertext of length %zu\n", ciphertext_len);

    /* We put all three keyring pointers in an array just to make it
     * easy to loop through them.
     */
    aws_cryptosdk_keyring *decrypting_keyrings[] = { multi_keyring, kms_keyring, escrow_keyring };

    for (int kr_idx = 0; kr_idx < 3; kr_idx++) {
        uint8_t plaintext_result[BUFFER_SIZE];
        size_t plaintext_result_len;

        encrypt_or_decrypt(
            alloc,
            decrypting_keyrings[kr_idx],
            AWS_CRYPTOSDK_DECRYPT,
            plaintext_result,
            BUFFER_SIZE,
            &plaintext_result_len,
            ciphertext,
            ciphertext_len);

        printf(">> Decrypted to plaintext of length %zu\n", plaintext_result_len);
        if (plaintext_original_len != plaintext_result_len) abort();
        if (memcmp(plaintext_original, plaintext_result, plaintext_result_len)) abort();
        printf(">> Decrypted plaintext matches original!\n");

        /* All sessions that referred to the keyring have already
         * been destroyed. So the keyring will be destroyed on this release.
         * Note, however, that destroying the multi-keyring in the first
         * iteration of this loop will not destroy the other two keyrings,
         * because we have not yet released the pointers to the other
         * keyrings that we received on keyring creation.
         */
        aws_cryptosdk_keyring_release(decrypting_keyrings[kr_idx]);
    }

    Aws::ShutdownAPI(options);
    return 0;
}
