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

#include <aws/core/utils/ARN.h>
#include <aws/cryptosdk/cpp/kms_keyring.h>
#include <aws/cryptosdk/session.h>

/* This example encrypts a string using a keyring configured with two KMS CMKs in
 * different regions and then performs the same decryption of the string with six
 * keyrings configured in various ways. Although all of the decrypting keyrings
 * are able to decrypt this message, their general behavior varies, and the comments
 * below explain the differences. These differences are most significant when
 * consumers of the Encryption SDK want to limit their calls to KMS either to
 * specific sets of CMKs or to specific regions.
 *
 * To test this functionality yourself, you must provide the two KMS Customer
 * Master Key ARNs as command-line arguments. The first key must be in
 * us-west-2, and the second key must be in eu-central-1. By changing the
 * KmsKeyring builder arguments, you can also use keys in other regions.
 */

void encrypt_string(
    struct aws_allocator *alloc,
    uint8_t *out_ciphertext,
    size_t out_ciphertext_buf_sz,
    size_t *out_ciphertext_len,
    const uint8_t *in_plaintext,
    size_t in_plaintext_len,
    const char *key_arn_us_west_2,
    const char *key_arn_eu_central_1) {
    struct aws_cryptosdk_keyring *kms_keyring =
        Aws::Cryptosdk::KmsKeyring::Builder().Build(key_arn_us_west_2, { key_arn_eu_central_1 });
    if (!kms_keyring) {
        abort();
    }

    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_keyring_2(alloc, AWS_CRYPTOSDK_ENCRYPT, kms_keyring);
    if (!session) abort();
    aws_cryptosdk_keyring_release(kms_keyring);

    /* For clarity, we set the commitment policy explicitly. The COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT
     * policy is selected by default in v2.0, so this is not required.
     */
    if (aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT)) {
        fprintf(stderr, "set_commitment_policy failed: %s", aws_error_debug_str(aws_last_error()));
        abort();
    }

    if (AWS_OP_SUCCESS !=
        aws_cryptosdk_session_process_full(
            session, out_ciphertext, out_ciphertext_buf_sz, out_ciphertext_len, in_plaintext, in_plaintext_len)) {
        abort();
    }
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
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_keyring_2(alloc, AWS_CRYPTOSDK_DECRYPT, kms_keyring);
    if (!session) abort();

    /* For clarity, we set the commitment policy explicitly. The COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT
     * policy is selected by default in v2.0, so this is not required.
     */
    if (aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT)) {
        fprintf(stderr, "set_commitment_policy failed: %s", aws_error_debug_str(aws_last_error()));
        abort();
    }

    if (AWS_OP_SUCCESS !=
        aws_cryptosdk_session_process_full(
            session, out_plaintext, out_plaintext_buf_sz, out_plaintext_len, in_ciphertext, in_ciphertext_len)) {
        abort();
    }
    aws_cryptosdk_session_destroy(session);
}

std::shared_ptr<Aws::KMS::KMSClient> create_kms_client(const Aws::String &region) {
    Aws::Client::ClientConfiguration client_config;
    client_config.region = region;
    return Aws::MakeShared<Aws::KMS::KMSClient>("AWS_SAMPLE_CODE", client_config);
}

#define BUFFER_SIZE 1024

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(
            stderr,
            "Usage: %s <key_arn_us_west_2> <key_arn_eu_central_1>\n"
            "key_arn_us_west_2 must be a KMS key in us-west-2,"
            "and key_arn_eu_central_1 must be a KMS key in eu-central-1.\n",
            argv[0]);
        exit(1);
    }

    const char *key_arn_us_west_2    = argv[1];
    const char *key_arn_eu_central_1 = argv[2];
    const char *aws_account_id       = argv[3];

    Aws::Utils::ARN parsed_arn_us_west_2(key_arn_us_west_2);

    struct aws_allocator *alloc         = aws_default_allocator();
    const char *plaintext_original      = "Hello world!";
    const size_t plaintext_original_len = strlen(plaintext_original);

    uint8_t ciphertext[BUFFER_SIZE];
    size_t ciphertext_len;

    aws_common_library_init(aws_default_allocator());
    aws_cryptosdk_load_error_strings();
    Aws::SDKOptions options;
    Aws::InitAPI(options);

    /* We encrypt a short string using two different KMS CMKs, one in us-west-2
     * and one in eu-central-1. This has the effect of encrypting the data key
     * separately with each CMK so that someone who has access to either key
     * can decrypt it.
     */
    encrypt_string(
        alloc,
        ciphertext,
        BUFFER_SIZE,
        &ciphertext_len,
        (const uint8_t *)plaintext_original,
        plaintext_original_len,
        key_arn_us_west_2,
        key_arn_eu_central_1);
    printf(">> Encrypted to ciphertext of length %zu\n", ciphertext_len);

    /* We will decrypt the same encrypted text repeatedly with several
     * different keyrings. All of these keyrings will do so successfully.
     */
    std::vector<struct aws_cryptosdk_keyring *> decryption_keyrings;

    /* This keyring has access to both keys, which is more than it needs.
     * It might call KMS in either region to decrypt, depending on whether it
     * comes across the first or second key ARN first as it scans the messages.
     * In this example, it will actually do its decryption using
     * key_arn_us_west_2, because that was the first ARN used for *encryption*.
     * However, if KMS in us-west-2 declines to decrypt the data key for any
     * reason, (e.g., permissions) it could still successfully decrypt the
     * string using key_arn_eu_central_1.
     */
    decryption_keyrings.push_back(
        Aws::Cryptosdk::KmsKeyring::Builder().Build(key_arn_eu_central_1, { key_arn_us_west_2 }));

    /* This keyring is guaranteed to only call KMS to attempt decryptions
     * in us-west-2, and it will only attempt to do so when it sees that
     * the message has been encrypted by this specific CMK.
     */
    decryption_keyrings.push_back(Aws::Cryptosdk::KmsKeyring::Builder().Build(key_arn_us_west_2));

    /* This keyring is guaranteed to only call KMS to attempt decryptions
     * in eu-central-1, and it will only attempt to do so when it sees that
     * the message has beeen encrypted by this specific CMK.
     */
    decryption_keyrings.push_back(Aws::Cryptosdk::KmsKeyring::Builder().Build(key_arn_eu_central_1));

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

    /* This will only attempt to decrypt using keys owned by the specified AWS
     * account. It will succeed if the message was encrypted with any KMS key
     * owned by the specified AWS account and for which you have Decrypt
     * permissions.
     */
    const Aws::String filter_account_id = parsed_arn_us_west_2.GetAccountId();
    std::shared_ptr<Aws::Cryptosdk::KmsKeyring::DiscoveryFilter> discovery_filter =
        Aws::Cryptosdk::KmsKeyring::DiscoveryFilter::Builder("aws").AddAccount(filter_account_id).Build();
    decryption_keyrings.push_back(Aws::Cryptosdk::KmsKeyring::Builder()
            .BuildDiscovery(discovery_filter));

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
