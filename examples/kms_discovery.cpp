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

const char *KEY_ARN_US_WEST_2    = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
const char *KEY_ARN_EU_CENTRAL_1 = "arn:aws:kms:eu-central-1:658956600833:key/75414c93-5285-4b57-99c9-30c1cf0a22c2";

void encrypt_string(
    struct aws_allocator *alloc,
    uint8_t *out_ciphertext,
    size_t out_ciphertext_buf_sz,
    size_t *out_ciphertext_len,
    const uint8_t *in_plaintext,
    size_t in_plaintext_len) {
    struct aws_cryptosdk_keyring *kms_keyring =
        Aws::Cryptosdk::KmsKeyring::Builder().Build(KEY_ARN_US_WEST_2, { KEY_ARN_EU_CENTRAL_1 });
    if (!kms_keyring) {
        abort();
    }

    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_default_cmm_new(alloc, kms_keyring);
    if (!cmm) abort();
    aws_cryptosdk_keyring_release(kms_keyring);

    struct aws_cryptosdk_session *session = aws_cryptosdk_session_new_from_cmm(alloc, AWS_CRYPTOSDK_ENCRYPT, cmm);
    if (!session) abort();
    aws_cryptosdk_cmm_release(cmm);

    if (AWS_OP_SUCCESS != aws_cryptosdk_session_set_message_size(session, in_plaintext_len)) {
        abort();
    }

    size_t in_plaintext_consumed;
    if (AWS_OP_SUCCESS != aws_cryptosdk_session_process(
                              session,
                              out_ciphertext,
                              out_ciphertext_buf_sz,
                              out_ciphertext_len,
                              in_plaintext,
                              in_plaintext_len,
                              &in_plaintext_consumed)) {
        abort();
    }
    if (!aws_cryptosdk_session_is_done(session)) abort();
    if (in_plaintext_consumed != in_plaintext_len) abort();
    aws_cryptosdk_session_destroy(session);
}

void decrypt_string(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_keyring *kms_keyring,
    uint8_t *out_plaintext,
    size_t out_plaintext_buf_sz,
    size_t *out_plaintext_len,
    const uint8_t *in_ciphertext,
    size_t in_ciphertext_len) {
    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_default_cmm_new(alloc, kms_keyring);
    if (!cmm) abort();

    struct aws_cryptosdk_session *session = aws_cryptosdk_session_new_from_cmm(alloc, AWS_CRYPTOSDK_DECRYPT, cmm);
    if (!session) abort();
    aws_cryptosdk_cmm_release(cmm);

    size_t in_ciphertext_consumed;
    if (AWS_OP_SUCCESS != aws_cryptosdk_session_process(
                              session,
                              out_plaintext,
                              out_plaintext_buf_sz,
                              out_plaintext_len,
                              in_ciphertext,
                              in_ciphertext_len,
                              &in_ciphertext_consumed)) {
        abort();
    }
    if (!aws_cryptosdk_session_is_done(session)) abort();
    if (in_ciphertext_consumed != in_ciphertext_len) abort();
    aws_cryptosdk_session_destroy(session);
}

std::shared_ptr<Aws::KMS::KMSClient> create_kms_client(const Aws::String &region) {
    Aws::Client::ClientConfiguration client_config;
    client_config.region = region;
    return Aws::MakeShared<Aws::KMS::KMSClient>("AWS_SAMPLE_CODE", client_config);
}

#define BUFFER_SIZE 1024

int main(int argc, char **argv) {
    struct aws_allocator *alloc         = aws_default_allocator();
    const char *plaintext_original      = "Hello world!";
    const size_t plaintext_original_len = strlen(plaintext_original);

    uint8_t ciphertext[BUFFER_SIZE];
    size_t ciphertext_len;

    aws_cryptosdk_load_error_strings();
    Aws::SDKOptions options;
    Aws::InitAPI(options);

    /* We encrypt a short string using two different KMS CMKs, one in us-west-2
     * and one in eu-central-1. This has the effect of encrypting the data key
     * separately with each CMK so that someone who has access to either key
     * can decrypt it.
     */
    encrypt_string(
        alloc, ciphertext, BUFFER_SIZE, &ciphertext_len, (const uint8_t *)plaintext_original, plaintext_original_len);
    printf(">> Encrypted to ciphertext of length %zu\n", ciphertext_len);

    /* We will decrypt the same encrypted text repeatedly with several
     * different keyrings. All of these keyrings will do so successfully.
     */
    std::vector<struct aws_cryptosdk_keyring *> decryption_keyrings;

    /* This keyring has access to both keys, which is more than it needs.
     * It might call KMS in either region to decrypt, depending on whether it
     * comes across the first or second key ARN first as it scans the messages.
     * In this example, it will actually do its decryption using
     * KEY_ARN_US_WEST_2, because that was the first ARN used for *encryption*.
     * However, if KMS in us-west-2 declines to decrypt the data key for any
     * reason, (e.g., permissions) it could still successfully decrypt the
     * string using KEY_ARN_EU_CENTRAL_1.
     */
    decryption_keyrings.push_back(
        Aws::Cryptosdk::KmsKeyring::Builder().Build(KEY_ARN_EU_CENTRAL_1, { KEY_ARN_US_WEST_2 }));

    /* This keyring is guaranteed to only call KMS to attempt decryptions
     * in us-west-2, and it will only attempt to do so when it sees that
     * the message has been encrypted by this specific CMK.
     */
    decryption_keyrings.push_back(Aws::Cryptosdk::KmsKeyring::Builder().Build(KEY_ARN_US_WEST_2));

    /* This keyring is guaranteed to only call KMS to attempt decryptions
     * in eu-central-1, and it will only attempt to do so when it sees that
     * the message has beeen encrypted by this specific CMK.
     */
    decryption_keyrings.push_back(Aws::Cryptosdk::KmsKeyring::Builder().Build(KEY_ARN_EU_CENTRAL_1));

    /* This is a discovery keyring, which you do not need to configure at all.
     * It will detect from the metadata in the encrypted message itself which
     * region to call KMS in, and as long as you have decrypt permissions on
     * any one of the CMKs used to encrypt it, you will be able to decrypt
     * the message. However, it might call KMS in any AWS region, based on
     * whichever CMKs were used in encryption.
     */
    decryption_keyrings.push_back(Aws::Cryptosdk::KmsKeyring::Builder().BuildDiscovery());

    /* This will only attempt KMS calls in us-west-2, even though it is not
     * configured with any specific CMKs. It will succeed if the message was
     * encrypted with any CMK in us-west-2 that you have decrypt privileges for.
     */
    decryption_keyrings.push_back(Aws::Cryptosdk::KmsKeyring::Builder()
                                      .WithKmsClient(create_kms_client(Aws::Region::US_WEST_2))
                                      .BuildDiscovery());

    /* This will only attempt KMS calls in eu-central-1, even though it is not
     * configured with any specific CMKs. It will succeed if the message was
     * encrypted with any CMK in eu-central-1 that you have decrypt privileges for.
     */
    decryption_keyrings.push_back(Aws::Cryptosdk::KmsKeyring::Builder()
                                      .WithKmsClient(create_kms_client(Aws::Region::EU_CENTRAL_1))
                                      .BuildDiscovery());

    for (struct aws_cryptosdk_keyring *keyring : decryption_keyrings) {
        uint8_t plaintext_result[BUFFER_SIZE];
        size_t plaintext_result_len;
        decrypt_string(
            alloc, keyring, plaintext_result, BUFFER_SIZE, &plaintext_result_len, ciphertext, ciphertext_len);
        printf(">> Decrypted to plaintext of length %zu\n", plaintext_result_len);

        if (plaintext_original_len != plaintext_result_len) abort();
        if (memcmp(plaintext_original, plaintext_result, plaintext_result_len)) abort();
        printf(">> Decrypted plaintext matches original!\n");
        aws_cryptosdk_keyring_release(keyring);
    }
    Aws::ShutdownAPI(options);
    return 0;
}
