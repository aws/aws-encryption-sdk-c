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
#include <stdlib.h>
#include <stdio.h>

#include <aws/core/Aws.h>

#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/session.h>
#include <aws/cryptosdk/kms_keyring.h>

#include <aws/core/client/ClientConfiguration.h>

void encrypt_string_test(struct aws_byte_buf * ct_out, struct aws_byte_buf * const pt_in) {
    const char * KEY_ARN = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
    const char * REGION = Aws::Region::US_WEST_2;

    struct aws_allocator * allocator = aws_default_allocator();

    struct Aws::Client::ClientConfiguration client_configuration;
    client_configuration.region = REGION;

    std::shared_ptr<Aws::KMS::KMSClient> kms_client = Aws::MakeShared<Aws::KMS::KMSClient>("Test KMS", client_configuration);

    auto kms_keyring = Aws::Cryptosdk::KmsKeyring::Builder().WithKmsClient(kms_client).Build({KEY_ARN});

    struct aws_cryptosdk_cmm * cmm = aws_cryptosdk_default_cmm_new(allocator, kms_keyring);
    if (!cmm) abort();
    aws_cryptosdk_keyring_release(kms_keyring);

    struct aws_cryptosdk_session * session = aws_cryptosdk_session_new_from_cmm(allocator, AWS_CRYPTOSDK_ENCRYPT, cmm);
    if (!session) abort();
    aws_cryptosdk_cmm_release(cmm);

    aws_cryptosdk_session_set_message_size(session, pt_in->len);

    size_t out_consumed, in_consumed;
    int encrypt_result = aws_cryptosdk_session_process(session, ct_out->buffer, ct_out->capacity, &ct_out->len,
                                                       pt_in->buffer, pt_in->len, &in_consumed) ;
    if (encrypt_result != AWS_OP_SUCCESS) abort();

    aws_cryptosdk_session_destroy(session);
}

void decrypt_string_test(struct aws_byte_buf * pt_out, struct aws_byte_buf const * ct_in) {
    const char * KEY_ARN = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
    const char * REGION = Aws::Region::US_WEST_2;

    struct aws_allocator * allocator = aws_default_allocator();

    struct Aws::Client::ClientConfiguration client_configuration;
    client_configuration.region = REGION;

    std::shared_ptr<Aws::KMS::KMSClient> kms_client = Aws::MakeShared<Aws::KMS::KMSClient>("Test KMS", client_configuration);

    auto kms_keyring = Aws::Cryptosdk::KmsKeyring::Builder().WithKmsClient(kms_client).Build({KEY_ARN});

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
    aws_load_error_strings();
    aws_cryptosdk_err_init_strings();

    Aws::SDKOptions::SDKOptions options;
    Aws::InitAPI(options);
    enum { BUFFER_SIZE = 1024 };

    struct aws_allocator * allocator = aws_default_allocator();

    struct aws_byte_buf plaintext_original = aws_byte_buf_from_c_str("Hello world!");

    //
    // Encrypt plaintext_original to ciphertext
    //
    uint8_t ct_buf[BUFFER_SIZE] = {0};
    struct aws_byte_buf ciphertext = aws_byte_buf_from_array(ct_buf, sizeof(ct_buf));

    encrypt_string_test(&ciphertext, &plaintext_original);

    printf(">> Encrypted to ciphertext of len %d\n", (int)ciphertext.len);

    //
    // Decrypt ciphertext to plaintext_result
    //
    uint8_t pt_buf[BUFFER_SIZE] = {0};
    struct aws_byte_buf plaintext_result = aws_byte_buf_from_array(pt_buf, sizeof(pt_buf));

    decrypt_string_test(&plaintext_result, &ciphertext);

    printf(">> Decrypted to plaintext of len %d with content [%s]\n", (int)plaintext_result.len, (char const *)plaintext_result.buffer);

    aws_byte_buf_clean_up_secure(&plaintext_result);

    Aws::ShutdownAPI(options);
}
