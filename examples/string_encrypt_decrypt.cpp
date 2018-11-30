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

#include <string.h>

#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/session.h>
#include <aws/cryptosdk/kms_keyring.h>

const char * KEY_ARN = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";

void encrypt_string_test(struct aws_byte_buf * ct_out, struct aws_byte_buf * const pt_in, struct aws_allocator * allocator) {
    auto kms_keyring = Aws::Cryptosdk::KmsKeyring::Builder().Build({KEY_ARN});

    struct aws_cryptosdk_cmm * cmm = aws_cryptosdk_default_cmm_new(allocator, kms_keyring);
    if (!cmm) abort();
    aws_cryptosdk_keyring_release(kms_keyring);

    struct aws_cryptosdk_session * session = aws_cryptosdk_session_new_from_cmm(allocator, AWS_CRYPTOSDK_ENCRYPT, cmm);
    if (!session) abort();
    aws_cryptosdk_cmm_release(cmm);

    aws_cryptosdk_session_set_message_size(session, pt_in->len);

    size_t out_consumed, in_consumed;
    int encrypt_result = aws_cryptosdk_session_process(session, ct_out->buffer, ct_out->capacity, &ct_out->len,
                                                       pt_in->buffer, pt_in->len, &in_consumed);
    if (encrypt_result != AWS_OP_SUCCESS) abort();

    aws_cryptosdk_session_destroy(session);
}

void decrypt_string_test(struct aws_byte_buf * pt_out, struct aws_byte_buf const * ct_in, struct aws_allocator * allocator) {
    auto kms_keyring = Aws::Cryptosdk::KmsKeyring::Builder().Build({KEY_ARN});

    struct aws_cryptosdk_cmm * cmm = aws_cryptosdk_default_cmm_new(allocator, kms_keyring);
    if (!cmm) abort();
    aws_cryptosdk_keyring_release(kms_keyring);

    struct aws_cryptosdk_session * session = aws_cryptosdk_session_new_from_cmm(allocator, AWS_CRYPTOSDK_DECRYPT, cmm);
    if (!session) abort();

    aws_cryptosdk_session_set_message_size(session, ct_in->len);

    size_t out_consumed, in_consumed;
    int decrypt_result = aws_cryptosdk_session_process(session, pt_out->buffer, pt_out->capacity, &pt_out->len,
                                                       ct_in->buffer, ct_in->len, &in_consumed) ;
    if (decrypt_result != AWS_OP_SUCCESS) abort();
}

int main() {
    aws_cryptosdk_load_error_strings();

    Aws::SDKOptions::SDKOptions options;
    Aws::InitAPI(options);
    const size_t BUFFER_SIZE = 1024;

    struct aws_allocator * allocator = aws_default_allocator();

    struct aws_byte_buf plaintext_original = aws_byte_buf_from_c_str("Hello world!");

    //
    // Encrypt plaintext_original to ciphertext
    //
    struct aws_byte_buf ciphertext ;
    aws_byte_buf_init(&ciphertext, allocator, BUFFER_SIZE);

    encrypt_string_test(&ciphertext, &plaintext_original, allocator);
    printf(">> Encrypted to ciphertext of len %d\n", (int)ciphertext.len);

    //
    // Decrypt ciphertext to plaintext_result
    //
    struct aws_byte_buf plaintext_result ;
    aws_byte_buf_init(&plaintext_result, allocator, BUFFER_SIZE);

    decrypt_string_test(&plaintext_result, &ciphertext, allocator);
    printf(">> Decrypted to plaintext of length %d\n", (int)plaintext_result.len);

    // Compare decrypted plaintext to original plaintext
    assert(plaintext_original.len == plaintext_result.len);
    assert(!memcmp(plaintext_original.buffer, plaintext_result.buffer, plaintext_original.len));

    aws_byte_buf_clean_up_secure(&plaintext_result);
    aws_byte_buf_clean_up(&ciphertext);

    Aws::ShutdownAPI(options);
}
