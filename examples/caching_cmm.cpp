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

#include <aws/cryptosdk/cache.h>
#include <aws/cryptosdk/cpp/kms_keyring.h>
#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/session.h>

#include <aws/common/encoding.h>
#include <aws/common/error.h>

#include <iostream>
#include <string>
#include <vector>

#include <aws/core/utils/logging/AWSLogging.h>
#include <aws/core/utils/logging/ConsoleLogSystem.h>

namespace {

void error(const char *description) {
    std::cerr << "Unexpected error in " << description << ": " << aws_error_str(aws_last_error()) << std::endl;
    abort();
}

std::vector<uint8_t> process_loop(struct aws_cryptosdk_session *session, const uint8_t *input, size_t in_len) {
    size_t out_needed = 1;
    size_t out_offset = 0, in_offset = 0;
    std::vector<uint8_t> buffer;

    while (!aws_cryptosdk_session_is_done(session)) {
        if (buffer.size() < out_offset + out_needed) {
            buffer.resize(out_needed + out_offset);
        }

        size_t bytes_written, bytes_read;
        if (aws_cryptosdk_session_process(
                session,
                buffer.data() + out_offset,
                buffer.size() - out_offset,
                &bytes_written,
                input + in_offset,
                in_len - in_offset,
                &bytes_read)) {
            error("session_process");
        }

        out_offset += bytes_written;
        in_offset += bytes_read;

        aws_cryptosdk_session_estimate_buf(session, &out_needed, NULL);
    }

    return buffer;
}

std::vector<uint8_t> encrypt(struct aws_allocator *alloc, struct aws_cryptosdk_cmm *cmm, const std::string &str) {
    struct aws_cryptosdk_session *session = aws_cryptosdk_session_new_from_cmm(alloc, AWS_CRYPTOSDK_ENCRYPT, cmm);
    if (!session) abort();

    if (aws_cryptosdk_session_set_message_size(session, str.size())) {
        error("set_message_size");
    }

    std::vector<uint8_t> buffer = process_loop(session, reinterpret_cast<const uint8_t *>(str.data()), str.size());

    aws_cryptosdk_session_destroy(session);

    return buffer;
}

std::string decrypt(
    struct aws_allocator *alloc, struct aws_cryptosdk_cmm *cmm, const std::vector<uint8_t> &ciphertext) {
    struct aws_cryptosdk_session *session = aws_cryptosdk_session_new_from_cmm(alloc, AWS_CRYPTOSDK_DECRYPT, cmm);
    if (!session) abort();

    std::vector<uint8_t> buffer = process_loop(session, ciphertext.data(), ciphertext.size());

    aws_cryptosdk_session_destroy(session);

    return std::string(buffer.begin(), buffer.end());
}

std::string base64_encode(const std::vector<uint8_t> &vec) {
    size_t b64_len;

    if (aws_base64_compute_encoded_len(vec.size(), &b64_len)) {
        error("aws_base64_compute_encoded_len");
    }

    std::vector<uint8_t> tmp;
    tmp.resize(b64_len);

    struct aws_byte_cursor cursor = aws_byte_cursor_from_array(vec.data(), vec.size());
    struct aws_byte_buf b64_buf   = aws_byte_buf_from_array(tmp.data(), tmp.size());

    if (aws_base64_encode(&cursor, &b64_buf)) {
        error("aws_base64_encode");
    }

    return std::string(tmp.begin(), tmp.end());
}

struct aws_cryptosdk_cmm *setup_cmm(struct aws_allocator *alloc, const char *key_arn) {
    struct aws_cryptosdk_keyring *kms_keyring = Aws::Cryptosdk::KmsKeyring::Builder().Build(key_arn);
    if (!kms_keyring) error("kms_keyring builder");

    struct aws_cryptosdk_cmm *default_cmm = aws_cryptosdk_default_cmm_new(alloc, kms_keyring);
    if (!default_cmm) error("default_cmm constructor");

    struct aws_cryptosdk_materials_cache *cache = aws_cryptosdk_materials_cache_local_new(alloc, 8);
    if (!cache) error("local cache constructor");

    /* The final two arguments of the call to create the caching CMM set the TTL of data keys in the cache. */
    struct aws_cryptosdk_cmm *caching_cmm =
        aws_cryptosdk_caching_cmm_new(alloc, cache, default_cmm, NULL, 60, AWS_TIMESTAMP_SECS);
    if (!caching_cmm) error("caching CMM constructor");

    // The caching_cmm object now holds references (directly or indirectly) to all the other objects;
    // we can now release our references so that the objects will be automatically cleaned up when we
    // eventually release the caching_cmm itself.
    aws_cryptosdk_keyring_release(kms_keyring);
    aws_cryptosdk_cmm_release(default_cmm);
    aws_cryptosdk_materials_cache_release(cache);

    return caching_cmm;
}

}  // namespace

int main(int argc, char **argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " key_arn string1 [string2 string3 ...]" << std::endl;
        return 1;
    }

    aws_cryptosdk_load_error_strings();
    Aws::SDKOptions options;
    Aws::InitAPI(options);

    // Initialize logging to show when KMS calls are made
    Aws::Utils::Logging::InitializeAWSLogging(
        Aws::MakeShared<Aws::Utils::Logging::ConsoleLogSystem>("CachingExample", Aws::Utils::Logging::LogLevel::Debug));

    struct aws_allocator *alloc   = aws_default_allocator();
    struct aws_cryptosdk_cmm *cmm = setup_cmm(alloc, argv[1]);

    std::vector<std::vector<uint8_t>> ciphertexts;

    for (int i = 2; i < argc; i++) {
        std::string str(argv[i]);

        std::vector<uint8_t> ciphertext = encrypt(alloc, cmm, str);
        std::cout << "Ciphertext for string \"" << str << "\":\n" << base64_encode(ciphertext) << "\n\n" << std::flush;
        ciphertexts.push_back(std::move(ciphertext));
    }

    std::cout << "\nDecrypting ciphertexts:\n";

    for (auto &ciphertext : ciphertexts) {
        auto plaintext = decrypt(alloc, cmm, ciphertext);

        std::cout << " - " << plaintext << "\n" << std::flush;
    }

    aws_cryptosdk_cmm_release(cmm);

    Aws::Utils::Logging::ShutdownAWSLogging();
    Aws::ShutdownAPI(options);

    return 0;
}
