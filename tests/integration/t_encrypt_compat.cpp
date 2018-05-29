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

#include "testing.h"

#include <memory>
#include <sstream>

#include <aws/common/encoding.h>
#include <aws/core/Aws.h>
#include <aws/lambda/LambdaClient.h>
#include <aws/lambda/model/InvokeRequest.h>
#include <aws/lambda/model/InvokeResult.h>
#include <aws/core/utils/Outcome.h>
#include <aws/core/utils/base64/Base64.h>

#include <aws/core/utils/logging/AWSLogging.h>
#include <aws/core/utils/logging/ConsoleLogSystem.h>

#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/session.h>

// This is a private symbol so the headers don't have extern "C" guards.
// We'll just define it directly.
extern "C" {
    int aws_cryptosdk_genrandom(uint8_t *buf, size_t len);
}

// This lambda function attempts to decrypt a base-64 encoded ciphertext
// encrypted with an all-zero data key.
static const char *decrypt_null_fn = "arn:aws:lambda:us-west-2:518866784541:function:AWSCryptoolsSDKOracleJavaLambda-Decrypt-1JPQJY7GZGKHK";

static int sdk_init_depth = 0;

class SDKInitializer {
private:
    Aws::SDKOptions options;
public:
    SDKInitializer() {
        using namespace Aws::Utils::Logging;
        if (!sdk_init_depth++) {
            Aws::InitAPI(options);
            Aws::Utils::Logging::InitializeAWSLogging(
                std::shared_ptr<Aws::Utils::Logging::LogSystemInterface>(
                    new Aws::Utils::Logging::ConsoleLogSystem(
                        Aws::Utils::Logging::LogLevel::Warn
                    )
                )
            );
        }
    }

    ~SDKInitializer() {
        if (!--sdk_init_depth) {
            Aws::Utils::Logging::ShutdownAWSLogging();
            Aws::ShutdownAPI(options);
        }
    }
};

static Aws::Lambda::LambdaClient lambda_client() {
    Aws::Client::ClientConfiguration config;
    config.region = Aws::String("us-west-2");

    return Aws::Lambda::LambdaClient(config);
}

#define ASSERT_OUTCOME(invocation, expected, size) \
    do { \
        if (!assert_successful_outcome(invocation, expected, size, #invocation, __FILE__, __LINE__)) { \
            return 1; \
        } \
    } while (0)

using Aws::Utils::Base64::Base64;
using Aws::Utils::ByteBuffer;

void hexdump(const uint8_t *buf, size_t size) {
    for (size_t row = 0; row < size; row += 16) {
        fprintf(stderr, "%08zx ", row);
        for (int idx = 0; idx < 16; idx++) {
            if (idx + row < size) {
                fprintf(stderr, "%s%02x", (idx == 8) ? "  " : " ", buf[idx + row]);
            } else {
                fprintf(stderr, (idx == 8) ? "    " : "   ");
            }
        }
        fprintf(stderr, "  |");
        for (int idx = 0; idx < 16 && idx + row < size; idx++) {
            uint8_t ch = buf[idx + row];
            fprintf(stderr, "%c", isprint(ch) ? ch : '.');
        }
        fprintf(stderr, "|\n");
    }
}

static int assert_successful_outcome(
    Aws::Lambda::Model::InvokeOutcome outcome,
    const uint8_t *expected,
    size_t expected_size,
    const char *debug_expr,
    const char *file,
    int line
) {
    (void)debug_expr;

    if (!outcome.IsSuccess()) {
        auto error = outcome.GetError();
        fprintf(stderr, "Lambda invocation failed at %s:%d: %s\n",
            file, line, error.GetMessage().c_str());
        return 0;
    }

    auto result = outcome.GetResultWithOwnership();
    auto &payload = result.GetPayload();

    int chunk_size = 4096;
    std::vector<char> payload_buf;
    bool eof = false;
    do {
        int offset = payload_buf.size();
        payload_buf.resize(offset + chunk_size, 0);

        payload.read((char *)&payload_buf[offset], chunk_size);
        eof = payload.gcount() != chunk_size;
        offset += payload.gcount();
        payload_buf.resize(offset, 0);
    } while (!eof);

    if (payload_buf.size() < 2 || payload_buf[0] != '"' || payload_buf[payload_buf.size() - 1] != '"' ||
        memchr(&payload_buf[1], '"', payload_buf.size() - 2) != NULL) {
        payload_buf.push_back(0);

        fprintf(stderr, "Lambda invocation returned something that wasn't a string at %s:%d: %s\n",
            file, line, &payload_buf[0]);
        return 0;
    }

    Aws::String payload_str(&payload_buf[1], payload_buf.size() - 2);
    auto raw_buf = Base64().Decode(payload_str);
    const uint8_t *raw_buf_p = raw_buf.GetLength() ? &raw_buf[0] : (const uint8_t *)"";

    if (raw_buf.GetLength() != expected_size || memcmp(expected, raw_buf_p, expected_size)) {
        fprintf(stderr, "Lambda invocation returned unexpected result at %s:%d. Expected:\n", file, line);
        hexdump(expected, expected_size);
        fprintf(stderr, "Actual:\n");
        hexdump(raw_buf_p, raw_buf.GetLength());
        return 0;
    }

    return 1;
}

static Aws::Lambda::Model::InvokeOutcome invoke(uint8_t *ciphertext, size_t length) {
    ByteBuffer ciphertext_buf(ciphertext, length);
    std::string json_buf("\"");

    json_buf += std::string(Base64().Encode(ciphertext_buf).c_str());
    json_buf += '"';

    auto client = lambda_client();
    Aws::Lambda::Model::InvokeRequest request;

    request.SetFunctionName(decrypt_null_fn);
    request.SetInvocationType(Aws::Lambda::Model::InvocationType::RequestResponse);
    auto body = std::make_shared<std::stringstream>(json_buf);
    request.SetBody(
        std::static_pointer_cast<Aws::IOStream>(body)
    );

    return client.Invoke(request);
}

static int test_basic() {
    uint8_t plaintext[] = "Hello, world!";

    uint8_t ciphertext[1024];

    size_t pt_consumed, ct_consumed;
    struct aws_cryptosdk_session *session = aws_cryptosdk_session_new(aws_default_allocator());

    aws_cryptosdk_session_init_encrypt(session);
    aws_cryptosdk_session_set_message_size(session, sizeof(plaintext));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_process(session,
        ciphertext, sizeof(ciphertext), &ct_consumed,
        plaintext, sizeof(plaintext), &pt_consumed
    ));

    TEST_ASSERT_INT_EQ(pt_consumed, sizeof(plaintext));
    TEST_ASSERT(aws_cryptosdk_session_is_done(session));

    aws_cryptosdk_session_destroy(session);

    hexdump(ciphertext, ct_consumed);

    ASSERT_OUTCOME(invoke(ciphertext, ct_consumed), plaintext, sizeof(plaintext));

    return 0;
}

static int test_framesize(size_t datasize, size_t framesize, bool early_size) {
    std::vector<uint8_t> plaintext;
    plaintext.resize(datasize);
    aws_cryptosdk_genrandom(&plaintext[0], datasize);

    std::vector<uint8_t> ciphertext;
    ciphertext.resize(plaintext.size());

    struct aws_cryptosdk_session *session = aws_cryptosdk_session_new(aws_default_allocator());
    aws_cryptosdk_session_init_encrypt(session);
    if (early_size) aws_cryptosdk_session_set_message_size(session, plaintext.size());

    size_t pt_offset = 0, ct_offset = 0;

    while (!aws_cryptosdk_session_is_done(session)) {
        size_t pt_need, ct_need;
        aws_cryptosdk_session_estimate_buf(session, &ct_need, &pt_need);

        size_t pt_available = std::min(pt_need, plaintext.size() - pt_offset);

        const uint8_t *pt_ptr = &plaintext[pt_offset];

        size_t ct_available = ct_need;
        ciphertext.resize(ct_offset + ct_need);
        uint8_t *ct_ptr = &ciphertext[ct_offset];

        size_t pt_consumed, ct_generated;

        TEST_ASSERT_SUCCESS(aws_cryptosdk_session_process(session,
            ct_ptr, ct_need, &ct_generated,
            pt_ptr, pt_available, &pt_consumed
        ));

        // Estimates can be off until the first call to process. We'll check
        // that we're making progress by re-estimating after calling process;
        // if we made no progress and the estimate is asking for more plaintext
        // than our limit, then something is wrong.
        aws_cryptosdk_session_estimate_buf(session, &ct_need, &pt_need);

        if (pt_need > plaintext.size() && ct_need <= ct_available && !pt_consumed && !ct_generated) {
            // Hmm... it seems to want more plaintext than we have available.
            // If we haven't set the precise size yet, then this is understandable;
            // it's also possible that we've not gotten to the body yet (in which case
            // we should see insufficient ciphertext space).
            // Otherwise something has gone wrong.
            TEST_ASSERT(!early_size);
            aws_cryptosdk_session_set_message_size(session, plaintext.size());
        }

        pt_offset += pt_consumed;
        ct_offset += ct_generated;
        ciphertext.resize(ct_offset);
    }

    ASSERT_OUTCOME(invoke(&ciphertext[0], ciphertext.size()), &plaintext[0], plaintext.size());

    aws_cryptosdk_session_destroy(session);

    return 0;
}

#define RUN_TEST(expr) \
    do { \
        const char *test_desc = #expr; \
        fprintf(stderr, "[RUNNING] %s ...\r", test_desc); \
        int result = (expr); \
        fprintf(stderr, "%s %s    \n", result ? "\n[ FAILED]" : "[ PASSED]", test_desc); \
        if (result) return 1; \
        final_result = final_result || result; \
    } while (0)


int main() {
    aws_load_error_strings();
    aws_cryptosdk_err_init_strings();

    SDKInitializer init;

    int final_result = 0;

    RUN_TEST(test_basic());
    RUN_TEST(test_framesize(0, 1024, true));
    RUN_TEST(test_framesize(0, 1024, false));
    RUN_TEST(test_framesize(1, 1, true));
    RUN_TEST(test_framesize(1, 1, false));
    RUN_TEST(test_framesize(1024, 1024, true));
    RUN_TEST(test_framesize(1024, 1024, false));
    RUN_TEST(test_framesize(1023, 1024, true));
    RUN_TEST(test_framesize(1023, 1024, false));
    RUN_TEST(test_framesize(1025, 1024, true));
    RUN_TEST(test_framesize(1025, 1024, false));
    RUN_TEST(test_framesize(0, 0, true));
    RUN_TEST(test_framesize(1, 0, true));
    RUN_TEST(test_framesize(1024, 0, true));

    return final_result;
}


