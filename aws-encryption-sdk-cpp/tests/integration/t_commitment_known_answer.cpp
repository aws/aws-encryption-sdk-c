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

#include <fstream>

#include <aws/common/encoding.h>
#include <aws/core/utils/ARN.h>
#include <aws/core/utils/Array.h>
#include <aws/core/utils/FileSystemUtils.h>
#include <aws/core/utils/HashingUtils.h>
#include <aws/core/utils/json/JsonSerializer.h>
#include <aws/core/utils/logging/AWSLogging.h>
#include <aws/core/utils/logging/ConsoleLogSystem.h>

#include <aws/cryptosdk/cpp/kms_keyring.h>
#include <aws/cryptosdk/enc_ctx.h>
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/multi_keyring.h>
#include <aws/cryptosdk/private/header.h>
#include <aws/cryptosdk/raw_aes_keyring.h>

#include "edks_utils.h"
#include "test_crypto.h"
#include "testutil.h"

using namespace Aws::Cryptosdk;
using namespace Aws::Utils::Json;

using Aws::SDKOptions;

const char *CLASS_CTAG = "Test KMS";

/* This special test key has been configured to allow Encrypt, Decrypt, and GenerateDataKey operations from any
 * AWS principal and should be used when adding new KMS tests.
 * You should never use it in production!
 */
const char *KEY_ARN_STR1        = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
const char *KEY_ARN_STR1_REGION = Aws::Region::US_WEST_2;

/*
 * These RAII-style logging classes will buffer log entries until .clear() is called on the LoggingRAII object.
 * If a test fails, RUN_TEST will return from main without calling clear, and the destructor on LoggingRAII will dump
 * the buffered log entries for the specific failed test to stderr before exiting.
 */
namespace {
class BufferedLogSystem : public Aws::Utils::Logging::FormattedLogSystem {
   private:
    std::mutex logMutex;
    std::vector<Aws::String> buffer;

   public:
    void clear() {
        std::lock_guard<std::mutex> guard(logMutex);

        buffer.clear();
    }

    void dump() {
        std::lock_guard<std::mutex> guard(logMutex);

        for (auto &str : buffer) {
            std::cerr << str;
        }
    }

    void Flush() {}

    BufferedLogSystem(Aws::Utils::Logging::LogLevel logLevel) : FormattedLogSystem(logLevel) {}

   protected:
    // Overrides FormattedLogSystem pure virtual function
    virtual void ProcessFormattedStatement(Aws::String &&statement) {
        std::lock_guard<std::mutex> guard(logMutex);

        buffer.push_back(std::move(statement));
    }
};

class LoggingRAII {
    std::shared_ptr<BufferedLogSystem> logSystem;

   public:
    LoggingRAII() {
        logSystem = Aws::MakeShared<BufferedLogSystem>("LoggingRAII", Aws::Utils::Logging::LogLevel::Info);

        Aws::Utils::Logging::InitializeAWSLogging(logSystem);
    }

    void clear() {
        logSystem->clear();
    }

    ~LoggingRAII() {
        Aws::Utils::Logging::ShutdownAWSLogging();

        logSystem->dump();
    }
};
}  // namespace

Aws::String run_single_test(aws_cryptosdk_keyring *kr, const JsonView &test) {
    auto pt_frames_obj  = test.GetObject("plaintext-frames");
    bool have_pt_frames = pt_frames_obj.IsListType();

    auto ciphertext_b64 = test.GetString("ciphertext");
    auto status         = test.GetBool("status");
    auto expected_ctx   = test.GetObject("encryption-context").GetAllObjects();

    Aws::Vector<uint8_t> expected_pt;

    if (have_pt_frames) {
        auto pt_frames = pt_frames_obj.AsArray();

        for (int i = 0; i < pt_frames.GetLength(); i++) {
            const JsonView frame = pt_frames.GetUnderlyingData()[i];
            auto str             = frame.AsString();

            for (int j = 0; j < str.size(); j++) {
                expected_pt.push_back(str[j]);
            }
        }
    }

    auto session = aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_DECRYPT, kr);
    if (!session) abort();

    if (aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT) !=
        AWS_OP_SUCCESS) {
        abort();
    }

    auto ciphertext = Aws::Utils::HashingUtils::Base64Decode(ciphertext_b64);

    Aws::Vector<uint8_t> plaintext(ciphertext.GetLength(), 0);

    size_t in_offset = 0, out_offset = 0;
    int result = AWS_OP_SUCCESS;

    while (!aws_cryptosdk_session_is_done(session)) {
        size_t consumed, produced;

        if (aws_cryptosdk_session_process(
                session,
                &plaintext[out_offset],
                plaintext.size() - out_offset,
                &produced,
                ciphertext.GetUnderlyingData() + in_offset,
                ciphertext.GetLength() - in_offset,
                &consumed) != AWS_OP_SUCCESS) {
            result = AWS_OP_ERR;
            break;
        }

        in_offset += consumed;
        out_offset += produced;
    }

    plaintext.resize(out_offset);

    int lasterr = aws_last_error();

    bool should_succeed = test.GetBool("status");

    if (result == AWS_OP_SUCCESS) {
        if (!should_succeed) {
            aws_cryptosdk_session_destroy(session);
            return "Expected failure; got success";
        }
    } else {
        aws_cryptosdk_session_destroy(session);

        if (!should_succeed) return "";

        return aws_error_str(lasterr);
    }

    if (have_pt_frames && plaintext != expected_pt) {
        fprintf(stderr, "=== Expected ===\n");
        hexdump(stderr, &expected_pt[0], expected_pt.size());
        fprintf(stderr, "=== Actual ===\n");
        hexdump(stderr, &plaintext[0], plaintext.size());
        return "Incorrect plaintext";
    }

    const struct aws_hash_table *enc_ctx = aws_cryptosdk_session_get_enc_ctx_ptr(session);
    struct aws_hash_iter iter            = aws_hash_iter_begin(enc_ctx);

    while (!aws_hash_iter_done(&iter)) {
        const aws_string *key   = reinterpret_cast<const aws_string *>(iter.element.key);
        const aws_string *value = reinterpret_cast<const aws_string *>(iter.element.value);

        Aws::String s_key(reinterpret_cast<const char *>(key->bytes), key->len);
        Aws::String s_value(reinterpret_cast<const char *>(value->bytes), value->len);

        auto it = expected_ctx.find(s_key);
        if (it == expected_ctx.end()) {
            return "Unexpected encryption context key: " + s_key;
        } else {
            auto actual   = s_value;
            auto expected = it->second.AsString();
            if (it->second.AsString() != s_value) {
                return "Wrong value for encryption context key: \"" + s_key + "\"; expected \"" + expected +
                       "\" actual \"" + actual + "\"";
            }
        }

        aws_hash_iter_next(&iter);
    }

    aws_cryptosdk_session_destroy(session);

    return "";
}

AWS_STRING_FROM_LITERAL(PROVIDER_NAME, "ProviderName");
AWS_STRING_FROM_LITERAL(KEY_ID, "KeyId");
static uint8_t ZERO_KEY[32] = { 0 };

bool known_answer_tests(LoggingRAII &logging, const char *filename) {
    std::fstream file(filename);
    JsonValue test_dataset(file);
    JsonView dataset_view = test_dataset.View();

    if (!dataset_view.IsObject() || !dataset_view.ValueExists("tests") ||
        !dataset_view.GetObject("tests").IsListType()) {
        std::cerr << "Malformed dataset" << std::endl;
        return false;
    }

    auto kms_keyring = Aws::Cryptosdk::KmsKeyring::Builder().Build(KEY_ARN_STR1);
    if (!kms_keyring) abort();

    aws_cryptosdk_keyring *gcm_keyring = aws_cryptosdk_raw_aes_keyring_new(
        aws_default_allocator(), PROVIDER_NAME, KEY_ID, ZERO_KEY, AWS_CRYPTOSDK_AES256);

    aws_cryptosdk_keyring *kr = aws_cryptosdk_multi_keyring_new(aws_default_allocator(), kms_keyring);
    aws_cryptosdk_multi_keyring_add_child(kr, gcm_keyring);
    aws_cryptosdk_keyring_release(gcm_keyring);

    bool ok = true;

    auto tests = dataset_view.GetArray("tests");
    for (int i = 0; i < tests.GetLength(); i++) {
        const auto test = tests.GetItem(i);

        std::cerr << "[RUNNING] " << test.GetString("comment") << std::flush;

        auto result = run_single_test(kr, test);
        std::cerr << "\r" << std::flush;
        if (result != "") {
            std::cout << "[ FAILED] " << test.GetString("comment") << std::endl << "          " << result << std::endl;
            ok = false;
        } else {
            std::cout << "[SUCCESS] " << test.GetString("comment") << std::endl;
        }
    }

    aws_cryptosdk_keyring_release(kr);

    return ok;
}

int main(int argc, char **argv) {
    aws_common_library_init(aws_default_allocator());
    aws_cryptosdk_load_error_strings();

    LoggingRAII logging;

    SDKOptions options;
    Aws::InitAPI(options);

    bool ok = known_answer_tests(logging, argv[1]);

    if (ok) {
        logging.clear();
    }

    Aws::ShutdownAPI(options);

    return ok ? 0 : 1;
}
