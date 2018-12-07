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

#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/kms_keyring.h>
#include <aws/cryptosdk/session.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s key_arn\n", argv[0]);
        return 1;
    }

    struct aws_allocator *alloc = aws_default_allocator();
    const char *plaintext_original = "Hello world!";
    const size_t plaintext_original_len = strlen(plaintext_original);

    const size_t BUFFER_SIZE = 1024;
    uint8_t ciphertext[BUFFER_SIZE];
    uint8_t plaintext_result[BUFFER_SIZE];

    aws_cryptosdk_load_error_strings();
    Aws::SDKOptions options;
    Aws::InitAPI(options);

    struct aws_cryptosdk_keyring *kms_keyring =
        Aws::Cryptosdk::KmsKeyring::Builder().Build({argv[1]});
    if (!kms_keyring) {
        printf("Failed to build KMS Keyring. Did you specify a valid KMS CMK ARN?\n");
        return 2;
    }

    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_default_cmm_new(alloc, kms_keyring);
    if (!cmm) abort();
    // We release the keyring, so it will live as long as the CMM does.
    aws_cryptosdk_keyring_release(kms_keyring);

    struct aws_cryptosdk_session *enc_session =
        aws_cryptosdk_session_new_from_cmm(alloc, AWS_CRYPTOSDK_ENCRYPT, cmm);
    if (!enc_session) abort();
    // We do not release the CMM, as we will reuse it in another session.

    if (AWS_OP_SUCCESS != aws_cryptosdk_session_set_message_size(enc_session,
                                                                 plaintext_original_len)) {
        abort();
    }

    size_t ciphertext_len;
    size_t plaintext_consumed;
    if (AWS_OP_SUCCESS != aws_cryptosdk_session_process(enc_session,
                                                        ciphertext,
                                                        BUFFER_SIZE,
                                                        &ciphertext_len,
                                                        (const uint8_t *)plaintext_original,
                                                        plaintext_original_len,
                                                        &plaintext_consumed)) {
        abort();
    }
    assert(plaintext_consumed == plaintext_original_len);
    aws_cryptosdk_session_destroy(enc_session);

    printf(">> Encrypted to ciphertext of length %ld\n", ciphertext_len);

    struct aws_cryptosdk_session *dec_session =
        aws_cryptosdk_session_new_from_cmm(alloc, AWS_CRYPTOSDK_DECRYPT, cmm);
    if (!dec_session) abort();
    // Now we release the CMM, so it will live as long as the session does.
    aws_cryptosdk_cmm_release(cmm);

    size_t plaintext_result_len;
    size_t ciphertext_consumed;
    if (AWS_OP_SUCCESS != aws_cryptosdk_session_process(dec_session,
                                                        plaintext_result,
                                                        BUFFER_SIZE,
                                                        &plaintext_result_len,
                                                        ciphertext,
                                                        ciphertext_len,
                                                        &ciphertext_consumed)) {
        abort();
    }
    assert(ciphertext_consumed == ciphertext_len);
    aws_cryptosdk_session_destroy(dec_session);

    printf(">> Decrypted to plaintext of length %ld\n", plaintext_result_len);

    assert(plaintext_original_len == plaintext_result_len);
    assert(!memcmp(plaintext_original, plaintext_result, plaintext_result_len));

    printf(">> Decrypted plaintext matches original!\n");

    Aws::ShutdownAPI(options);
    return 0;
}
