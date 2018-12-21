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
#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/raw_aes_keyring.h>
#include <aws/cryptosdk/session.h>
#include <stdio.h>

#define BUFFER_SIZE 1024

/* Encrypts/decrypts the entire input buffer using the CMM provided. */
void encrypt_or_decrypt(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_cmm *cmm,
    enum aws_cryptosdk_mode mode,
    uint8_t *output,
    size_t output_buf_sz,
    size_t *output_len,
    const uint8_t *input,
    size_t input_len) {
    struct aws_cryptosdk_session *session = aws_cryptosdk_session_new_from_cmm(alloc, mode, cmm);
    assert(session);

    if (mode == AWS_CRYPTOSDK_ENCRYPT) {
        assert(AWS_OP_SUCCESS == aws_cryptosdk_session_set_message_size(session, input_len));
    }

    size_t input_consumed;
    assert(
        AWS_OP_SUCCESS ==
        aws_cryptosdk_session_process(session, output, output_buf_sz, output_len, input, input_len, &input_consumed));
    assert(aws_cryptosdk_session_is_done(session));
    assert(input_consumed == input_len);
    aws_cryptosdk_session_destroy(session);
}

/* This example does a simple string encryption using the raw AES keyring.
 * This keyring does local encryption and decryption of data keys using a
 * wrapping key (i.e., master key) provided as a simple byte array. We
 * recommend using a service such as AWS KMS or a secure device such as a
 * hardware security module (HSM) that does not expose wrapping keys and
 * performs data key encryption within a secure boundary. However, if you
 * have a use case for doing encryption using local wrapping keys, the raw
 * AES keyring will do AES-GCM encryption of data keys with the AES-128,
 * AES-192, or AES-256 wrapping key that you provide.
 *
 * The raw AES keyring does the equivalent encryption and decryption as the
 * AWS Encryption SDK for Java's JceMasterKey when used with a secret key
 * and the AWS Encryption SDK for Python's RawMasterKey when used in
 * symmetric mode. Data encrypted by any of the SDKs can be decrypted by
 * any of the others using the same wrapping key.
 */
int main(int argc, char **argv) {
    if (argc < 2) {
        /* To run this test just generate a file of 128, 192, or 256 random bits
         * to use as your encryption key and give the filename as the argument.
         *
         * Here are example command lines on Mac/UNIX-like systems that will
         * generate key files:
         *
         * dd bs=16 count=1 < /dev/random > aes_128_key
         * dd bs=24 count=1 < /dev/random > aes_192_key
         * dd bs=32 count=1 < /dev/random > aes_256_key
         *
         * Warning: keeping your master encryption key on disk unencrypted is
         * not recommended in a production setting.
         */
        fprintf(
            stderr,
            "Usage: %s key_file\n"
            "Key file is a raw binary file of 128, 192, or 256 bits.\n",
            argv[0]);
        return 1;
    }

    struct aws_allocator *alloc = aws_default_allocator();

    uint8_t wrapping_key[32];

    FILE *key_file = fopen(argv[1], "rb");
    assert(key_file);

    /* Read in up to 256 bits from the key file. AWS_CRYPTOSDK_AES_256/192/128
     * are equal to the appropriate AES key length in *bytes*.
     */
    size_t wrapping_key_len = fread(wrapping_key, 1, 32, key_file);

    /* Check if key file was wrong size. We need to read one more byte before
     * feof(keyfile) will be true for a file of exactly 256 bits. */
    uint8_t throwaway;
    fread(&throwaway, 1, 1, key_file);
    if (!feof(key_file) || !(wrapping_key_len == AWS_CRYPTOSDK_AES_256 || wrapping_key_len == AWS_CRYPTOSDK_AES_192 ||
                             wrapping_key_len == AWS_CRYPTOSDK_AES_128)) {
        fclose(key_file);
        fprintf(stderr, "Key file must be 128, 192, or 256 bits only.\n");

        /* When handling secret keys, it is always a good practice to zero
         * them out when you are finished.
         */
        aws_secure_zero(wrapping_key, AWS_CRYPTOSDK_AES_256);
        return 2;
    }
    fclose(key_file);

    /* You must assign all of your wrapping keys a namespace and name.
     * Do not use the string "aws-kms" as that is the namespace reserved
     * for KMS keys, but otherwise the namespace can be whatever you choose.
     *
     * Every wrapping key you use should have a unique name within the
     * namespace. You can think of the name as a bookkeeping mechanism to
     * keep track of your different keys, but note that the namespace and
     * name will be unencrypted metadata in the ciphertext format, so they
     * should not contain any secret information.
     *
     * When attempting to decrypt ciphertexts, the keyring will compare the
     * namespace and name in the ciphertext message format with those
     * configured in your keyring to determine whether to even attempt
     * decryption, so the keyring used for decryption must be configured with
     * not only the same wrapping key but also the same namespace and name
     * in order to decrypt successfully.
     *
     * The AWS Encryption SDKs for Java and Python use the term "Provider ID"
     * for namespace and "Key ID" for name in their JceMasterKey and RawMasterKey
     * objects. The Provider ID and Key ID used in those must match the name
     * and namespace used in the raw AES keyring for interoperability.
     *
     * In the AWS Encryption SDK for C, you must define the namespace and
     * name as the AWS String type from the aws-c-common library. You can
     * do this using one of the aws_string_new_from_* functions in that library
     * or using the following static string macro. The macro can only be used
     * for a string literal hard-coded in your source code. Using it enables an
     * optimization in which no extra copies of it are created in memory
     * during the use of the keyring.
     */
    AWS_STATIC_STRING_FROM_LITERAL(wrapping_key_namespace, "my master keys");
    /* Defines struct aws_string *wrapping_key_namespace, which does not need
     * to be destroyed.
     */

    struct aws_string *wrapping_key_name = aws_string_new_from_c_str(alloc, "key #1");
    /* This will need to be destroyed. Suitable for use for C-strings that are
     * created at runtime.
     */

    struct aws_cryptosdk_keyring *keyring = aws_cryptosdk_raw_aes_keyring_new(
        alloc, wrapping_key_namespace, wrapping_key_name, wrapping_key, wrapping_key_len);
    assert(keyring);

    /* The keyring holds its own copy of the strings and key, so we destroy the string
     * we created and zero out the bytes of the key.
     */
    aws_string_destroy((void *)wrapping_key_name);
    aws_secure_zero(wrapping_key, wrapping_key_len);

    /* We create a default Cryptographic Materials Manager (CMM) using this keyring. */
    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_default_cmm_new(alloc, keyring);
    assert(cmm);

    /* We release the pointer on the keyring so that it will be destroyed when the
     * CMM is destroyed. The CMM will be used for both encrypt and decrypt.
     */
    aws_cryptosdk_keyring_release(keyring);

    const char *plaintext_original      = "Hello world!";
    const size_t plaintext_original_len = strlen(plaintext_original);

    uint8_t ciphertext[BUFFER_SIZE];
    uint8_t plaintext_result[BUFFER_SIZE];
    size_t ciphertext_len;
    size_t plaintext_result_len;

    encrypt_or_decrypt(
        alloc,
        cmm,
        AWS_CRYPTOSDK_ENCRYPT,
        ciphertext,
        BUFFER_SIZE,
        &ciphertext_len,
        (const uint8_t *)plaintext_original,
        plaintext_original_len);
    printf(">> Encrypted to ciphertext of length %zu\n", ciphertext_len);

    encrypt_or_decrypt(
        alloc,
        cmm,
        AWS_CRYPTOSDK_DECRYPT,
        plaintext_result,
        BUFFER_SIZE,
        &plaintext_result_len,
        ciphertext,
        ciphertext_len);
    printf(">> Decrypted to plaintext of length %zu\n", plaintext_result_len);

    assert(plaintext_original_len == plaintext_result_len);
    assert(!memcmp(plaintext_original, plaintext_result, plaintext_result_len));
    printf(">> Decrypted plaintext matches original!\n");

    /* Releasing the CMM causes both the CMM and keyring to be destroyed.
     * The destruction of the raw AES keyring also causes the internal copy
     * of the wrapping key to be securely zeroed before deallocation.
     */
    aws_cryptosdk_cmm_release(cmm);

    return 0;
}
