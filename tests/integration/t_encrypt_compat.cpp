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
                        //Aws::Utils::Logging::LogLevel::Trace
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

    std::vector<char> payload_buf;
    bool eof = false;
    do {
        int to_read = 4096;
        int offset = payload_buf.size();
        payload_buf.resize(offset + to_read, 0);

        payload.read((char *)&payload_buf[offset], to_read);
        eof = payload.gcount() != to_read;
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

    if (raw_buf.GetLength() != expected_size || memcmp(expected, &raw_buf[0], expected_size)) {
        fprintf(stderr, "Lambda invocation returned unexpected result at %s:%d. Expected:\n", file, line);
        hexdump(expected, expected_size);
        fprintf(stderr, "Actual:\n");
        hexdump(&raw_buf[0], raw_buf.GetLength());
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

static int test() {
    uint8_t ciphertext[] = {
        0x01, 0x80, 0x03, 0x78, 0x24, 0xd8, 0xf4, 0x60, 0x3e, 0xa9, 0xc1, 0x66,
        0x85, 0x8e, 0x6d, 0x55, 0xd3, 0x1b, 0x78, 0xd0, 0x00, 0x5f, 0x00, 0x01,
        0x00, 0x15, 0x61, 0x77, 0x73, 0x2d, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f,
        0x2d, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0x00,
        0x44, 0x41, 0x73, 0x45, 0x78, 0x44, 0x35, 0x2f, 0x43, 0x53, 0x79, 0x49,
        0x50, 0x6b, 0x6e, 0x4f, 0x6e, 0x57, 0x67, 0x6f, 0x73, 0x33, 0x69, 0x6c,
        0x43, 0x61, 0x64, 0x39, 0x4e, 0x55, 0x49, 0x45, 0x79, 0x72, 0x47, 0x41,
        0x2f, 0x58, 0x33, 0x43, 0x41, 0x39, 0x51, 0x6d, 0x74, 0x61, 0x72, 0x57,
        0x30, 0x54, 0x58, 0x48, 0x6a, 0x56, 0x70, 0x56, 0x79, 0x78, 0x2f, 0x78,
        0x50, 0x58, 0x4d, 0x6c, 0x76, 0x67, 0x51, 0x3d, 0x3d, 0x00, 0x01, 0x00,
        0x04, 0x6e, 0x75, 0x6c, 0x6c, 0x00, 0x04, 0x6e, 0x75, 0x6c, 0x6c, 0x00,
        0x04, 0x6e, 0x75, 0x6c, 0x6c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x88, 0x72, 0x9d, 0x82, 0x66, 0x0a, 0x41, 0x77, 0x3c,
        0x53, 0x39, 0x72, 0x7e, 0xa4, 0x54, 0x3b, 0xff, 0xff, 0xff, 0xff, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0d, 0x2b, 0x40, 0x10, 0x6a, 0x3e,
        0xfd, 0xab, 0x39, 0x2e, 0xe8, 0x52, 0x85, 0x74, 0x0d, 0x21, 0xa1, 0xc9,
        0x71, 0x03, 0x54, 0xdd, 0xd0, 0xce, 0xa5, 0x69, 0x5b, 0xbf, 0x51, 0x2b,
        0x00, 0x67, 0x30, 0x65, 0x02, 0x31, 0x00, 0xba, 0x33, 0x0b, 0xed, 0x8a,
        0xb7, 0xdd, 0x57, 0xaf, 0xff, 0x1c, 0xd2, 0x3b, 0x54, 0xf3, 0x0a, 0x32,
        0x8a, 0x30, 0xe8, 0xdc, 0xac, 0xb0, 0x11, 0x3f, 0x0b, 0xf6, 0x90, 0xd2,
        0x9f, 0x12, 0x87, 0xe0, 0x95, 0xf1, 0xb3, 0x27, 0xb1, 0x40, 0x46, 0x09,
        0xc7, 0x00, 0xed, 0xbb, 0x7c, 0x62, 0x85, 0x02, 0x30, 0x1c, 0x93, 0x56,
        0x49, 0x3b, 0xd7, 0xc6, 0xb1, 0x94, 0xab, 0x8f, 0x8c, 0x0e, 0xeb, 0x86,
        0x92, 0x0b, 0x80, 0xb8, 0x81, 0xde, 0xf2, 0x47, 0x4a, 0x02, 0x58, 0x13,
        0xf2, 0x8c, 0x31, 0x61, 0xea, 0x8e, 0xa1, 0xd6, 0x51, 0xe8, 0xac, 0xbb,
        0x46, 0xc0, 0x16, 0xa2, 0xac, 0x01, 0x8c, 0xa2, 0x27
    };
    uint8_t expected[] = "Hello, world!";

    ASSERT_OUTCOME(invoke(ciphertext, sizeof(ciphertext)), expected, sizeof(expected) - 1);

    return 0;
}

int main() {
    SDKInitializer init;

    fprintf(stderr, "[RUNNING] Encrypt compat test...\r");

    int result = test();

    fprintf(stderr, "%s Encrypt compat test    \n", result ? "\n[ FAILED]" : "[ PASSED]");

    return result;
}


