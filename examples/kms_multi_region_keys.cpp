/*
 * Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/core/utils/ARN.h>
#include <aws/cryptosdk/cpp/kms_keyring.h>
#include <aws/cryptosdk/cpp/kms_mrk_keyring.h>
#include <aws/cryptosdk/session.h>

/* This example demonstrates how to use the KmsMrkAwareSymmetricKeyring to
 * encrypt and decrypt data in different regions, using an AWS KMS multi-Region
 * key.
 */

int encrypt(
    const char *key_arn,
    uint8_t *ciphertext,
    size_t ciphertext_buf_sz,
    size_t &ciphertext_len,
    const uint8_t *plaintext,
    size_t plaintext_len) {
    /* Initialize the multi-Region key keyring and a session using the keyring.
     * After creating the session, release the keyring reference to ensure
     * memory is deallocated correctly.
     */
    struct aws_cryptosdk_keyring *keyring = Aws::Cryptosdk::KmsMrkAwareSymmetricKeyring::Builder().Build(key_arn);
    if (!keyring) {
        fprintf(stderr, "Failed to build encryption keyring\n");
        return AWS_OP_ERR;
    }
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, keyring);
    aws_cryptosdk_keyring_release(keyring);
    if (!session) {
        fprintf(stderr, "Failed to create encryption session\n");
        return AWS_OP_ERR;
    }

    /* Encrypt the data. If the operation fails, clean up the session. */
    if (AWS_OP_SUCCESS != aws_cryptosdk_session_process_full(
                              session, ciphertext, ciphertext_buf_sz, &ciphertext_len, plaintext, plaintext_len)) {
        fprintf(stderr, "Encryption failed\n");
        aws_cryptosdk_session_destroy(session);
        return AWS_OP_ERR;
    }

    /* The operation succeeded. Clean up the session. */
    fprintf(stderr, "Encryption succeeded\n");
    aws_cryptosdk_session_destroy(session);
    return AWS_OP_SUCCESS;
}

int decrypt(
    const char *key_arn,
    uint8_t *plaintext,
    size_t plaintext_buf_sz,
    size_t &plaintext_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len) {
    /* Initialize the multi-Region key keyring and a session using the keyring.
     * After creating the session, release the keyring reference to ensure
     * memory is deallocated correctly.
     */
    struct aws_cryptosdk_keyring *keyring = Aws::Cryptosdk::KmsMrkAwareSymmetricKeyring::Builder().Build(key_arn);
    if (!keyring) {
        fprintf(stderr, "Failed to build decryption keyring\n");
        return AWS_OP_ERR;
    }
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_DECRYPT, keyring);
    aws_cryptosdk_keyring_release(keyring);
    if (!session) {
        fprintf(stderr, "Failed to create decryption session\n");
        return AWS_OP_ERR;
    }

    /* Decrypt the data. If the operation fails, clean up the session. */
    if (AWS_OP_SUCCESS != aws_cryptosdk_session_process_full(
                              session, plaintext, plaintext_buf_sz, &plaintext_len, ciphertext, ciphertext_len)) {
        fprintf(stderr, "Decryption failed\n");
        aws_cryptosdk_session_destroy(session);
        return AWS_OP_ERR;
    }

    /* The operation succeeded. Clean up the session. */
    fprintf(stderr, "Decryption succeeded\n");
    aws_cryptosdk_session_destroy(session);
    return AWS_OP_SUCCESS;
}

int decrypt_discovery(
    const Aws::String region,
    const Aws::Vector<Aws::String> account_ids,
    uint8_t *plaintext,
    size_t plaintext_buf_sz,
    size_t &plaintext_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len) {
    /* Construct a discovery filter for the desired account IDs. This is
     * optional, and if you do not want to restrict decryption keys, you can
     * skip this step.
     */
    const std::shared_ptr<Aws::Cryptosdk::KmsKeyring::DiscoveryFilter> discovery_filter =
        Aws::Cryptosdk::KmsKeyring::DiscoveryFilter::Builder("aws").WithAccounts(account_ids).Build();
    if (!discovery_filter) {
        fprintf(stderr, "Failed to build discovery filter\n");
        return AWS_OP_ERR;
    }

    /* Create a KMS client in the desired region. */
    Aws::Client::ClientConfiguration client_config;
    client_config.region = region;
    const std::shared_ptr<Aws::KMS::KMSClient> kms_client =
        Aws::MakeShared<Aws::KMS::KMSClient>("AWS_SAMPLE_CODE", client_config);

    /* Initialize the multi-Region key keyring in discovery mode, and a session
     * using the keyring. If you do not want to restrict decryption keys, omit
     * the discovery filter argument in the BuildDiscovery call.
     *
     * After creating the session, release the keyring
     * reference to ensure memory is deallocated correctly.
     */
    struct aws_cryptosdk_keyring *keyring = Aws::Cryptosdk::KmsMrkAwareSymmetricKeyring::Builder()
                                                .WithKmsClient(kms_client)
                                                .BuildDiscovery(region, discovery_filter);
    if (!keyring) {
        fprintf(stderr, "Failed to build discovery decryption keyring\n");
        return AWS_OP_ERR;
    }
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_DECRYPT, keyring);
    aws_cryptosdk_keyring_release(keyring);
    if (!session) {
        fprintf(stderr, "Failed to create discovery decryption session\n");
        return AWS_OP_ERR;
    }

    /* Decrypt the data. If the operation fails, clean up the session. */
    if (AWS_OP_SUCCESS != aws_cryptosdk_session_process_full(
                              session, plaintext, plaintext_buf_sz, &plaintext_len, ciphertext, ciphertext_len)) {
        fprintf(stderr, "Decryption in discovery mode failed\n");
        aws_cryptosdk_session_destroy(session);
        return AWS_OP_ERR;
    }

    /* The operation succeeded. Clean up the session. */
    fprintf(stderr, "Decryption in discovery mode succeeded\n");
    aws_cryptosdk_session_destroy(session);
    return AWS_OP_SUCCESS;
}

#define BUFFER_SIZE 1024

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(
            stderr,
            "Usage: %s <key_arn_1> <key_arn_2>\n"
            "key_arn_1 and key_arn_2 must be KMS multi-Region keys in different regions.\n",
            argv[0]);
        exit(1);
    }

    const char *key_arn_1 = argv[1];
    const char *key_arn_2 = argv[2];

    Aws::Utils::ARN parsed_arn_1(key_arn_1);
    Aws::Utils::ARN parsed_arn_2(key_arn_2);
    if (!parsed_arn_1 || !parsed_arn_2) {
        fprintf(stderr, "Provided key ARNs are invalid\n");
        return AWS_OP_ERR;
    }
    if (parsed_arn_1.GetRegion() == parsed_arn_2.GetRegion()) {
        fprintf(stderr, "Provided key ARNs must be in different regions.\n");
        return AWS_OP_ERR;
    }

    aws_common_library_init(aws_default_allocator());
    aws_cryptosdk_load_error_strings();
    Aws::SDKOptions options;
    Aws::InitAPI(options);

    const Aws::String discovery_region = parsed_arn_2.GetRegion();
    const Aws::Vector<Aws::String> discovery_account_ids{ parsed_arn_2.GetAccountId() };

    int ret;

    /* Encrypt the plaintext using the first multi-Region key. */
    const char *plaintext_original      = "Hello world!";
    const size_t plaintext_original_len = strlen(plaintext_original);
    uint8_t ciphertext[BUFFER_SIZE];
    size_t ciphertext_len;
    ret = encrypt(
        key_arn_1,
        ciphertext,
        BUFFER_SIZE,
        ciphertext_len,
        (const uint8_t *)plaintext_original,
        plaintext_original_len);
    if (ret != AWS_OP_SUCCESS) {
        fprintf(stderr, "Error on encrypt: %s\n", aws_error_str(aws_last_error()));
        goto done;
    }

    /* Decrypt the ciphertext using the second multi-Region key, which is in another region. */
    uint8_t plaintext_decrypted[BUFFER_SIZE];
    size_t plaintext_decrypted_len;
    ret = decrypt(key_arn_2, plaintext_decrypted, BUFFER_SIZE, plaintext_decrypted_len, ciphertext, ciphertext_len);
    if (ret != AWS_OP_SUCCESS) {
        fprintf(stderr, "Error on decrypt: %s\n", aws_error_str(aws_last_error()));
        goto done;
    }

    /* Verify that the decrypted plaintext matches the original plaintext. */
    if (plaintext_original_len != plaintext_decrypted_len ||
        memcmp(plaintext_original, plaintext_decrypted, plaintext_original_len)) {
        fprintf(stderr, "Decrypted plaintext doesn't match original plaintext!\n");
        ret = AWS_OP_ERR;
        goto done;
    }

    /* For demonstration purposes, decrypt the ciphertext in discovery mode (again, using the second key). */
    memset(plaintext_decrypted, 0, BUFFER_SIZE);
    plaintext_decrypted_len = 0;
    ret                     = decrypt_discovery(
        discovery_region,
        discovery_account_ids,
        plaintext_decrypted,
        BUFFER_SIZE,
        plaintext_decrypted_len,
        ciphertext,
        ciphertext_len);
    if (ret != AWS_OP_SUCCESS) {
        fprintf(stderr, "Error on decrypt in discovery mode: %s\n", aws_error_str(aws_last_error()));
        goto done;
    }

    /* Verify again that the decrypted plaintext matches the original plaintext. */
    if (plaintext_original_len != plaintext_decrypted_len ||
        memcmp(plaintext_original, plaintext_decrypted, plaintext_original_len)) {
        fprintf(stderr, "Decrypted plaintext doesn't match original plaintext!\n");
        ret = AWS_OP_ERR;
        goto done;
    }

done:
    Aws::ShutdownAPI(options);
    return ret;
}
