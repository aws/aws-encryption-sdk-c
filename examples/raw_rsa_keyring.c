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
#include <aws/cryptosdk/raw_rsa_keyring.h>
#include <aws/cryptosdk/session.h>
#include <stdio.h>

#define BUFFER_SIZE 4096

/* Encrypts/decrypts the entire input buffer using the keyring provided. */
void encrypt_or_decrypt_with_keyring(
    struct aws_allocator *alloc,
    uint8_t *output,
    size_t output_buf_sz,
    size_t *output_len,
    const uint8_t *input,
    size_t input_len,
    enum aws_cryptosdk_mode mode,
    struct aws_cryptosdk_keyring *keyring) {
    struct aws_cryptosdk_session *session = aws_cryptosdk_session_new_from_keyring_2(alloc, mode, keyring);
    if (!session) abort();

    /* For clarity, we set the commitment policy explicitly. The COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT
     * policy is selected by default in v2.0, so this is not required.
     */
    if (aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT)) {
        fprintf(stderr, "set_commitment_policy failed: %s", aws_error_debug_str(aws_last_error()));
        abort();
    }

    if (AWS_OP_SUCCESS !=
        aws_cryptosdk_session_process_full(session, output, output_buf_sz, output_len, input, input_len))
        abort();
    aws_cryptosdk_session_destroy(session);
}

/* Allocates an array with the contents of the file and one null byte at the end. */
char *read_file_into_buffer(const char *filename) {
    FILE *in_file = fopen(filename, "rb");
    if (!in_file) return NULL;

    fseek(in_file, 0L, SEEK_END);
    size_t file_size = ftell(in_file);
    rewind(in_file);

    char *data = (char *)malloc(file_size + 1);
    if (data) {
        data[file_size] = '\0';
        if (file_size != fread(data, 1, file_size, in_file)) {
            free(data);
            data = NULL;
        }
    }
    fclose(in_file);
    return data;
}

/* This example does a simple string encryption using the raw RSA keyring.
 * This keyring does local encryption of data keys using a wrapping key
 * (i.e., master key) provided as an RSA public key PEM file, and/or
 * local decryption of data keys using a wrapping key provided as an RSA
 * private key PEM file. The RSA encryption can be done with a variety
 * of padding modes. See cipher.h for the list of support padding modes.
 *
 * The raw RSA keyring does the equivalent encryption and decryption as the
 * AWS Encryption SDK for Java's JceMasterKey when used with a private and
 * public key pair and the AWS Encryption SDK for Python's RawMasterKey when
 * used in asymmetric mode. Data encrypted by any of the SDKs can be decrypted
 * by any of the others using the same wrapping key.
 */
int main(int argc, char **argv) {
    aws_common_library_init(aws_default_allocator());
    aws_cryptosdk_load_error_strings();

    if (argc < 3) {
        fprintf(stderr, "Usage: %s private_key_pem public_key_pem\n", argv[0]);
        return 1;
    }

    char *public_key_pem = read_file_into_buffer(argv[2]);
    if (!public_key_pem) {
        fprintf(stderr, "Error reading public key PEM file.\n");
        return 2;
    }

    char *private_key_pem = read_file_into_buffer(argv[1]);
    if (!private_key_pem) {
        fprintf(stderr, "Error reading private key PEM file.\n");
        free(public_key_pem);
        return 3;
    }

    struct aws_allocator *alloc = aws_default_allocator();

    /* See the comments in the raw_aes_encrypt_decrypt.c example for details
     * on wrapping key namespaces and names.
     */
    AWS_STATIC_STRING_FROM_LITERAL(wrapping_key_namespace, "my master keys");
    AWS_STATIC_STRING_FROM_LITERAL(wrapping_key_name, "key #2");

    /* We create a raw RSA keyring capable of encryption and decryption by
     * giving it a private key and public key pair in PEM format. Alternatively,
     * you may create a raw RSA keyring with only one of the PEM files by
     * setting the other parameter to NULL, but then that keyring will
     * only be capable of either encryption or decryption.
     *
     * In order for an RSA keyring to properly decrypt data encrypted by
     * another RSA keyring, all of the following must be true:
     *
     * (1) The two keyrings' wrapping key namespaces are identical.
     * (2) The two keyrings' wrapping key names are identical.
     * (3) The public key used by the encrypting keyring was derived from
     *     the private key used by the decrypting keyring.
     * (4) Both keyrings are set to the same padding mode.
     *
     * The last point is important. The data format of the encrypted data keys
     * generated by the raw RSA keyring does not store the padding mode used,
     * so the AWS Encryption SDK cannot detect the padding mode on decrypt.
     * It must be manually configured before decryption to the same mode that
     * was used on encryption.
     */
    struct aws_cryptosdk_keyring *keyring = aws_cryptosdk_raw_rsa_keyring_new(
        alloc,
        wrapping_key_namespace,
        wrapping_key_name,
        private_key_pem,
        public_key_pem,
        AWS_CRYPTOSDK_RSA_OAEP_SHA256_MGF1);
    if (!keyring) abort();

    /* The raw RSA keyring keeps its own copies of the PEM files, so we free
     * our own buffers, but first we zero out the bytes of the private key.
     */
    aws_secure_zero(private_key_pem, strlen(private_key_pem));
    free(private_key_pem);
    free(public_key_pem);

    const char *plaintext_original      = "Hello world!";
    const size_t plaintext_original_len = strlen(plaintext_original);

    uint8_t ciphertext[BUFFER_SIZE];
    uint8_t plaintext_result[BUFFER_SIZE];
    size_t ciphertext_len;
    size_t plaintext_result_len;

    encrypt_or_decrypt_with_keyring(
        alloc,
        ciphertext,
        BUFFER_SIZE,
        &ciphertext_len,
        (const uint8_t *)plaintext_original,
        plaintext_original_len,
        AWS_CRYPTOSDK_ENCRYPT,
        keyring);
    printf(">> Encrypted to ciphertext of length %zu\n", ciphertext_len);

    encrypt_or_decrypt_with_keyring(
        alloc,
        plaintext_result,
        BUFFER_SIZE,
        &plaintext_result_len,
        ciphertext,
        ciphertext_len,
        AWS_CRYPTOSDK_DECRYPT,
        keyring);
    printf(">> Decrypted to plaintext of length %zu\n", plaintext_result_len);

    if (plaintext_original_len != plaintext_result_len) abort();
    if (memcmp(plaintext_original, plaintext_result, plaintext_result_len)) abort();
    printf(">> Decrypted plaintext matches original!\n");

    /* The destruction of the raw RSA keyring causes the internal copy
     * of the private key to be securely zeroed before deallocation.
     */
    aws_cryptosdk_keyring_release(keyring);

    return 0;
}
