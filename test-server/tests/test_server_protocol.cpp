/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <aws/cryptosdk/error.h>

#include "bridge.h"
#include "cbor.h"
#include "http.h"
#include "server.h"

using esdk_test_server::cbor::Value;

#define CHECK(cond)                                                                   \
    do {                                                                              \
        if (!(cond)) {                                                                \
            std::fprintf(stderr, "FAILED: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
            return 1;                                                                 \
        }                                                                             \
    } while (0)

namespace {

const char *const OP_PATH = "/service/ESDKTestServer/operation/";

struct HttpResult {
    int status = 0;
    std::vector<uint8_t> body;
};

/** One blocking HTTP request against the local server; a fresh connection each call. */
HttpResult post(
    uint16_t port,
    const std::string &path,
    const std::vector<std::pair<std::string, std::string>> &headers,
    const std::vector<uint8_t> &body) {
    HttpResult result;
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return result;

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return result;
    }

    std::string head = "POST " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\n";
    for (const auto &header : headers) head += header.first + ": " + header.second + "\r\n";
    head += "Content-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n";
    (void)!::send(fd, head.data(), head.size(), 0);
    if (!body.empty()) (void)!::send(fd, body.data(), body.size(), 0);

    std::vector<uint8_t> raw;
    uint8_t chunk[8192];
    for (;;) {
        ssize_t got = ::recv(fd, chunk, sizeof(chunk), 0);
        if (got <= 0) break;
        raw.insert(raw.end(), chunk, chunk + got);
    }
    ::close(fd);

    std::string text(raw.begin(), raw.end());
    size_t header_end = text.find("\r\n\r\n");
    if (header_end == std::string::npos) return result;
    result.status = std::atoi(text.c_str() + text.find(' ') + 1);
    result.body.assign(raw.begin() + header_end + 4, raw.end());
    return result;
}

std::vector<std::pair<std::string, std::string>> protocol_headers() {
    return { { "smithy-protocol", "rpc-v2-cbor" }, { "Content-Type", "application/cbor" } };
}

HttpResult call(uint16_t port, const std::string &operation, const Value &request) {
    return post(port, OP_PATH + operation, protocol_headers(), esdk_test_server::cbor::encode(request));
}

Value decode_body(const HttpResult &result) {
    return esdk_test_server::cbor::decode(result.body.data(), result.body.size());
}

std::string error_type(const HttpResult &result) {
    Value body        = decode_body(result);
    const Value *type = body.find("__type");
    return type ? type->text : "";
}

const char *const GENERIC = "aws.cryptography.esdk.testserver#GenericServerError";
const char *const ESDK    = "aws.cryptography.esdk.testserver#ESDKClientError";

Value raw_aes_keyring(uint8_t key_fill, size_t key_len = 32) {
    std::vector<uint8_t> key(key_len);
    for (size_t i = 0; i < key.size(); i++) key[i] = static_cast<uint8_t>(key_fill + i);
    return Value::make_map(
        { { Value::make_text("RawAes"),
            Value::make_map(
                { { Value::make_text("keyNamespace"), Value::make_text("esdk-test-server") },
                  { Value::make_text("keyName"), Value::make_text("protocol-test-key") },
                  { Value::make_text("wrappingKey"), Value::make_bytes(std::move(key)) },
                  { Value::make_text("wrappingAlg"), Value::make_text("ALG_AES256_GCM_IV12_TAG16") } }) } });
}

Value create_client_request(Value keyring) {
    Value default_cmm = Value::make_map({ { Value::make_text("keyring"), std::move(keyring) } });
    Value cmm         = Value::make_map({ { Value::make_text("Default"), std::move(default_cmm) } });
    Value config =
        Value::make_map({ { Value::make_text("commitmentPolicy"), Value::make_text("REQUIRE_ENCRYPT_REQUIRE_DECRYPT") },
                          { Value::make_text("cmm"), std::move(cmm) } });
    return Value::make_map({ { Value::make_text("config"), std::move(config) } });
}

std::string create_client(uint16_t port, Value keyring) {
    HttpResult result = call(port, "CreateClient", create_client_request(std::move(keyring)));
    if (result.status != 200) return "";
    Value body      = decode_body(result);
    const Value *id = body.find("clientId");
    return id ? id->text : "";
}

Value ec_value(const std::vector<std::pair<std::string, std::string>> &pairs) {
    std::vector<std::pair<Value, Value>> entries;
    for (const auto &pair : pairs) {
        entries.emplace_back(Value::make_text(pair.first), Value::make_text(pair.second));
    }
    return Value::make_map(std::move(entries));
}

const std::vector<uint8_t> PLAINTEXT = { 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l', ' ',
                                         't', 'e', 's', 't', ' ', 'b', 'o', 'd', 'y' };

uint16_t server_port = 0;

int test_round_trip_with_context_and_introspection() {
    std::string client_id = create_client(server_port, raw_aes_keyring(0));
    CHECK(!client_id.empty());
    CHECK(client_id.size() == 36 && client_id[8] == '-');

    Value encrypt_request = Value::make_map(
        { { Value::make_text("clientId"), Value::make_text(client_id) },
          { Value::make_text("plaintext"), Value::make_bytes(PLAINTEXT) },
          { Value::make_text("encryptionContext"), ec_value({ { "purpose", "test" } }) },
          { Value::make_text("algorithmSuiteId"), Value::make_text("ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY") } });
    HttpResult encrypted = call(server_port, "Encrypt", encrypt_request);
    CHECK(encrypted.status == 200);
    Value encrypt_response  = decode_body(encrypted);
    const Value *ciphertext = encrypt_response.find("ciphertext");
    CHECK(ciphertext && !ciphertext->bytes.empty());

    Value decrypt_request =
        Value::make_map({ { Value::make_text("clientId"), Value::make_text(client_id) },
                          { Value::make_text("ciphertext"), Value::make_bytes(ciphertext->bytes) },
                          { Value::make_text("encryptionContext"), ec_value({ { "purpose", "test" } }) } });
    HttpResult decrypted = call(server_port, "Decrypt", decrypt_request);
    CHECK(decrypted.status == 200);
    Value response = decode_body(decrypted);
    CHECK(response.find("plaintext") && response.find("plaintext")->bytes == PLAINTEXT);
    CHECK(response.find("algorithmSuiteId"));
    CHECK(response.find("algorithmSuiteId")->text == "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY");
    const Value *context = response.find("encryptionContext");
    CHECK(context && context->find("purpose") && context->find("purpose")->text == "test");

    // Empty plaintext round-trips.
    Value empty_encrypt        = Value::make_map({ { Value::make_text("clientId"), Value::make_text(client_id) },
                                            { Value::make_text("plaintext"), Value::make_bytes({}) } });
    HttpResult empty_encrypted = call(server_port, "Encrypt", empty_encrypt);
    CHECK(empty_encrypted.status == 200);
    Value empty_encrypt_response = decode_body(empty_encrypted);
    Value empty_decrypt          = Value::make_map(
        { { Value::make_text("clientId"), Value::make_text(client_id) },
          { Value::make_text("ciphertext"), Value::make_bytes(empty_encrypt_response.find("ciphertext")->bytes) } });
    HttpResult empty_decrypted = call(server_port, "Decrypt", empty_decrypt);
    CHECK(empty_decrypted.status == 200);
    Value empty_decrypt_response = decode_body(empty_decrypted);
    CHECK(empty_decrypt_response.find("plaintext")->bytes.empty());
    return 0;
}

int test_stream_variants_round_trip() {
    std::string client_id = create_client(server_port, raw_aes_keyring(0));
    CHECK(!client_id.empty());

    // A payload spanning several frames at a small frame length.
    std::vector<uint8_t> plaintext(100000);
    for (size_t i = 0; i < plaintext.size(); i++) plaintext[i] = static_cast<uint8_t>(i * 31);

    Value encrypt_request = Value::make_map({ { Value::make_text("clientId"), Value::make_text(client_id) },
                                              { Value::make_text("plaintext"), Value::make_bytes(plaintext) },
                                              { Value::make_text("frameLength"), Value::make_int(1024) } });
    HttpResult encrypted  = call(server_port, "EncryptStream", encrypt_request);
    CHECK(encrypted.status == 200);
    Value encrypt_response  = decode_body(encrypted);
    const Value *ciphertext = encrypt_response.find("ciphertext");
    CHECK(ciphertext);

    Value decrypt_request =
        Value::make_map({ { Value::make_text("clientId"), Value::make_text(client_id) },
                          { Value::make_text("ciphertext"), Value::make_bytes(ciphertext->bytes) } });
    HttpResult decrypted = call(server_port, "DecryptStream", decrypt_request);
    CHECK(decrypted.status == 200);
    Value decrypt_response = decode_body(decrypted);
    CHECK(decrypt_response.find("plaintext")->bytes == plaintext);

    // Blob-encrypted messages decrypt through the stream variant too.
    Value blob_encrypt        = Value::make_map({ { Value::make_text("clientId"), Value::make_text(client_id) },
                                           { Value::make_text("plaintext"), Value::make_bytes(PLAINTEXT) } });
    HttpResult blob_encrypted = call(server_port, "Encrypt", blob_encrypt);
    CHECK(blob_encrypted.status == 200);
    Value blob_response = decode_body(blob_encrypted);
    Value cross_decrypt = Value::make_map(
        { { Value::make_text("clientId"), Value::make_text(client_id) },
          { Value::make_text("ciphertext"), Value::make_bytes(blob_response.find("ciphertext")->bytes) } });
    HttpResult cross_decrypted = call(server_port, "DecryptStream", cross_decrypt);
    CHECK(cross_decrypted.status == 200);
    Value cross_response = decode_body(cross_decrypted);
    CHECK(cross_response.find("plaintext")->bytes == PLAINTEXT);
    return 0;
}

int test_plaintext_length_bound() {
    std::string client_id = create_client(server_port, raw_aes_keyring(0));
    CHECK(!client_id.empty());

    Value within_bound = Value::make_map(
        { { Value::make_text("clientId"), Value::make_text(client_id) },
          { Value::make_text("plaintext"), Value::make_bytes(PLAINTEXT) },
          { Value::make_text("plaintextLengthBound"), Value::make_int(static_cast<int64_t>(PLAINTEXT.size())) } });
    CHECK(call(server_port, "EncryptStream", within_bound).status == 200);

    Value over_bound = Value::make_map(
        { { Value::make_text("clientId"), Value::make_text(client_id) },
          { Value::make_text("plaintext"), Value::make_bytes(PLAINTEXT) },
          { Value::make_text("plaintextLengthBound"), Value::make_int(static_cast<int64_t>(PLAINTEXT.size() - 1)) } });
    HttpResult rejected = call(server_port, "EncryptStream", over_bound);
    CHECK(rejected.status == 400);
    CHECK(error_type(rejected) == ESDK);
    return 0;
}

int test_bad_protocol_headers_rejected() {
    std::vector<uint8_t> body = esdk_test_server::cbor::encode(Value::make_map({}));

    HttpResult no_protocol =
        post(server_port, std::string(OP_PATH) + "CreateClient", { { "Content-Type", "application/cbor" } }, body);
    CHECK(no_protocol.status == 400);
    CHECK(error_type(no_protocol) == GENERIC);

    HttpResult bad_content_type = post(
        server_port,
        std::string(OP_PATH) + "CreateClient",
        { { "smithy-protocol", "rpc-v2-cbor" }, { "Content-Type", "text/plain" } },
        body);
    CHECK(bad_content_type.status == 400);
    CHECK(error_type(bad_content_type) == GENERIC);

    HttpResult wrong_service =
        post(server_port, "/service/NotThisService/operation/CreateClient", protocol_headers(), body);
    CHECK(wrong_service.status == 400);
    CHECK(error_type(wrong_service) == GENERIC);
    return 0;
}

int test_unknown_operation_rejected() {
    HttpResult result = call(server_port, "NoSuchOperation", Value::make_map({}));
    CHECK(result.status == 400);
    CHECK(error_type(result) == GENERIC);
    return 0;
}

int test_malformed_cbor_rejected() {
    HttpResult result = post(server_port, std::string(OP_PATH) + "CreateClient", protocol_headers(), { 0xBF, 0x00 });
    CHECK(result.status == 400);
    CHECK(error_type(result) == GENERIC);
    return 0;
}

int test_unknown_client_id_rejected() {
    Value request     = Value::make_map({ { Value::make_text("clientId"), Value::make_text("not-a-registered-client") },
                                      { Value::make_text("plaintext"), Value::make_bytes(PLAINTEXT) } });
    HttpResult result = call(server_port, "Encrypt", request);
    CHECK(result.status == 400);
    CHECK(error_type(result) == GENERIC);

    Value body           = decode_body(result);
    const Value *message = body.find("message");
    CHECK(message && message->text.find("unknown clientId") != std::string::npos);
    return 0;
}

int test_invalid_configs_rejected() {
    // A 16-byte wrapping key under a 256-bit wrapping algorithm.
    HttpResult short_key = call(server_port, "CreateClient", create_client_request(raw_aes_keyring(0, 16)));
    CHECK(short_key.status == 400);
    CHECK(error_type(short_key) == GENERIC);

    // No CMM variant set.
    Value config =
        Value::make_map({ { Value::make_text("commitmentPolicy"), Value::make_text("REQUIRE_ENCRYPT_REQUIRE_DECRYPT") },
                          { Value::make_text("cmm"), Value::make_map({}) } });
    HttpResult no_variant =
        call(server_port, "CreateClient", Value::make_map({ { Value::make_text("config"), std::move(config) } }));
    CHECK(no_variant.status == 400);
    CHECK(error_type(no_variant) == GENERIC);
    return 0;
}

int test_bad_frame_length_rejected() {
    std::string client_id = create_client(server_port, raw_aes_keyring(0));
    CHECK(!client_id.empty());
    Value request     = Value::make_map({ { Value::make_text("clientId"), Value::make_text(client_id) },
                                      { Value::make_text("plaintext"), Value::make_bytes(PLAINTEXT) },
                                      { Value::make_text("frameLength"), Value::make_int(-16) } });
    HttpResult result = call(server_port, "Encrypt", request);
    CHECK(result.status == 400);
    CHECK(error_type(result) == ESDK);
    return 0;
}

int test_esdk_failures_are_client_errors() {
    // Encrypting with the reserved signature key in the caller's encryption
    // context fails inside the ESDK's default CMM.
    std::string encrypt_id = create_client(server_port, raw_aes_keyring(0));
    std::string decrypt_id = create_client(server_port, raw_aes_keyring(101));
    CHECK(!encrypt_id.empty() && !decrypt_id.empty());

    Value reserved_request = Value::make_map(
        { { Value::make_text("clientId"), Value::make_text(encrypt_id) },
          { Value::make_text("plaintext"), Value::make_bytes(PLAINTEXT) },
          { Value::make_text("encryptionContext"), ec_value({ { "aws-crypto-public-key", "any-value" } }) } });
    HttpResult reserved = call(server_port, "Encrypt", reserved_request);
    CHECK(reserved.status == 400);
    CHECK(error_type(reserved) == ESDK);

    // Decrypting with a different wrapping key fails inside the ESDK.
    Value encrypt_request = Value::make_map({ { Value::make_text("clientId"), Value::make_text(encrypt_id) },
                                              { Value::make_text("plaintext"), Value::make_bytes(PLAINTEXT) } });
    HttpResult encrypted  = call(server_port, "Encrypt", encrypt_request);
    CHECK(encrypted.status == 200);
    Value encrypt_response = decode_body(encrypted);

    Value decrypt_request = Value::make_map(
        { { Value::make_text("clientId"), Value::make_text(decrypt_id) },
          { Value::make_text("ciphertext"), Value::make_bytes(encrypt_response.find("ciphertext")->bytes) } });
    HttpResult decrypted = call(server_port, "Decrypt", decrypt_request);
    CHECK(decrypted.status == 400);
    CHECK(error_type(decrypted) == ESDK);
    return 0;
}

int test_reproduced_context_mismatch_rejected() {
    std::string client_id = create_client(server_port, raw_aes_keyring(0));
    CHECK(!client_id.empty());

    Value encrypt_request =
        Value::make_map({ { Value::make_text("clientId"), Value::make_text(client_id) },
                          { Value::make_text("plaintext"), Value::make_bytes(PLAINTEXT) },
                          { Value::make_text("encryptionContext"), ec_value({ { "purpose", "test" } }) } });
    HttpResult encrypted = call(server_port, "Encrypt", encrypt_request);
    CHECK(encrypted.status == 200);
    Value encrypt_response          = decode_body(encrypted);
    std::vector<uint8_t> ciphertext = encrypt_response.find("ciphertext")->bytes;

    Value mismatched =
        Value::make_map({ { Value::make_text("clientId"), Value::make_text(client_id) },
                          { Value::make_text("ciphertext"), Value::make_bytes(ciphertext) },
                          { Value::make_text("encryptionContext"), ec_value({ { "purpose", "tampered" } }) } });
    HttpResult rejected = call(server_port, "Decrypt", mismatched);
    CHECK(rejected.status == 400);
    CHECK(error_type(rejected) == ESDK);
    return 0;
}

int test_caching_cmm_round_trip() {
    Value default_cmm = Value::make_map({ { Value::make_text("keyring"), raw_aes_keyring(0) } });
    Value caching     = Value::make_map({ { Value::make_text("underlyingCMM"),
                                        Value::make_map({ { Value::make_text("Default"), std::move(default_cmm) } }) },
                                      { Value::make_text("cacheLimitTtlSeconds"), Value::make_int(60) } });
    Value cmm         = Value::make_map({ { Value::make_text("Caching"), std::move(caching) } });
    Value config =
        Value::make_map({ { Value::make_text("commitmentPolicy"), Value::make_text("REQUIRE_ENCRYPT_REQUIRE_DECRYPT") },
                          { Value::make_text("cmm"), std::move(cmm) } });
    HttpResult created =
        call(server_port, "CreateClient", Value::make_map({ { Value::make_text("config"), std::move(config) } }));
    CHECK(created.status == 200);
    Value created_response = decode_body(created);
    std::string client_id  = created_response.find("clientId")->text;

    Value encrypt_request = Value::make_map({ { Value::make_text("clientId"), Value::make_text(client_id) },
                                              { Value::make_text("plaintext"), Value::make_bytes(PLAINTEXT) } });
    HttpResult encrypted  = call(server_port, "Encrypt", encrypt_request);
    CHECK(encrypted.status == 200);
    Value encrypt_response = decode_body(encrypted);

    Value decrypt_request = Value::make_map(
        { { Value::make_text("clientId"), Value::make_text(client_id) },
          { Value::make_text("ciphertext"), Value::make_bytes(encrypt_response.find("ciphertext")->bytes) } });
    HttpResult decrypted = call(server_port, "Decrypt", decrypt_request);
    CHECK(decrypted.status == 200);
    Value decrypt_response = decode_body(decrypted);
    CHECK(decrypt_response.find("plaintext")->bytes == PLAINTEXT);
    return 0;
}

int test_raw_rsa_round_trips_per_padding() {
    // The repository's own raw-RSA test key pair
    // (tests/lib/raw_rsa_keyring_test_vectors.c).
    static const char public_pem[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC78fCDSGwNcJFXtP6XQ/48kDzU\n"
        "FUFT22YiJZJDVOkaj9Sq0xEeiuB3CVuDv41+Cc4bacijKRwbW5ZsXRLDjEwsPxLD\n"
        "coCVtVdA+APPNpaOiGOOBMdZA9vubMHBqq+vPwRAtksbWb7H+EyStManM2SalZCz\n"
        "CRBKg64VmYdZng/XZwIDAQAB\n"
        "-----END PUBLIC KEY-----\n";
    static const char private_pem[] =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALvx8INIbA1wkVe0\n"
        "/pdD/jyQPNQVQVPbZiIlkkNU6RqP1KrTER6K4HcJW4O/jX4JzhtpyKMpHBtblmxd\n"
        "EsOMTCw/EsNygJW1V0D4A882lo6IY44Ex1kD2+5swcGqr68/BEC2SxtZvsf4TJK0\n"
        "xqczZJqVkLMJEEqDrhWZh1meD9dnAgMBAAECgYByskygIcNnVEoup1MzhxgRZ8jn\n"
        "eO08OsmSjzE6jAgR4LLdaR+qbwBbRMenmG/F+j/g9Oavw/fWLkeXbBl2YxlcXlQk\n"
        "R2u21OVVgDaChJx1LJM+qwthvqRANm1qTWh2/aVUyV4phsuNjnmpDkveaCklffIc\n"
        "r2J6ppUXCuETvniv2QJBAPFISRh/cLGqdrqQSX9bZEUU8Wsu8Xj5fJBYXkKg/+8u\n"
        "B0/Rrwk6ktpkwzOChk8OC3Gvv9pwNbFv0UqRdLwqxOsCQQDHaMWxGabRlMwZY5ry\n"
        "SPkV2jFBt+q9VEv2wn7d9irNQih8Iou0Te0r8Opej7yUEy/BPQ9PesVV8p/kKzcT\n"
        "9Yh1AkAq4i4brIrbCPERN5PYjuXDYXWHF1DTr4P0I8CdFwBmAkhKZ3o0qbRwHHiV\n"
        "Lx2v708ZZaMzr73bS4RnPHMC/pcBAkBYpuu84HqZkl1qrC2mqWqTnH1piiqCIYfk\n"
        "HHPqmhZNSqxVA8a4Uiyu7FxFzgE4k48Xid3Up/AzVbpf5haGeRJBAkEAnVB7Icg/\n"
        "osxu+ddL3m5V9uF81vxfFWjLN2CIOVM0xSzbh8ygyZFe+QftPHt0QGamVo4kWZQl\n"
        "PvsBm2PORwzpAg==\n"
        "-----END PRIVATE KEY-----\n";

    auto rsa_keyring = [&](const char *padding) {
        std::vector<uint8_t> pub(public_pem, public_pem + sizeof(public_pem) - 1);
        std::vector<uint8_t> priv(private_pem, private_pem + sizeof(private_pem) - 1);
        return Value::make_map(
            { { Value::make_text("RawRsa"),
                Value::make_map({ { Value::make_text("keyNamespace"), Value::make_text("esdk-test-server") },
                                  { Value::make_text("keyName"), Value::make_text("protocol-test-rsa-key") },
                                  { Value::make_text("paddingScheme"), Value::make_text(padding) },
                                  { Value::make_text("publicKey"), Value::make_bytes(std::move(pub)) },
                                  { Value::make_text("privateKey"), Value::make_bytes(std::move(priv)) } }) } });
    };

    // The library's supported paddings round-trip.
    const char *supported[] = { "PKCS1", "OAEP_SHA1_MGF1", "OAEP_SHA256_MGF1" };
    for (const char *padding : supported) {
        std::string client_id = create_client(server_port, rsa_keyring(padding));
        CHECK(!client_id.empty());

        Value encrypt_request = Value::make_map({ { Value::make_text("clientId"), Value::make_text(client_id) },
                                                  { Value::make_text("plaintext"), Value::make_bytes(PLAINTEXT) } });
        HttpResult encrypted  = call(server_port, "Encrypt", encrypt_request);
        CHECK(encrypted.status == 200);
        Value encrypt_response = decode_body(encrypted);

        Value decrypt_request = Value::make_map(
            { { Value::make_text("clientId"), Value::make_text(client_id) },
              { Value::make_text("ciphertext"), Value::make_bytes(encrypt_response.find("ciphertext")->bytes) } });
        HttpResult decrypted = call(server_port, "Decrypt", decrypt_request);
        CHECK(decrypted.status == 200);
        Value decrypt_response = decode_body(decrypted);
        CHECK(decrypt_response.find("plaintext")->bytes == PLAINTEXT);
    }

    // The paddings the library lacks are a modeled error at CreateClient.
    const char *unsupported[] = { "OAEP_SHA384_MGF1", "OAEP_SHA512_MGF1" };
    for (const char *padding : unsupported) {
        HttpResult rejected = call(server_port, "CreateClient", create_client_request(rsa_keyring(padding)));
        CHECK(rejected.status == 400);
        CHECK(error_type(rejected) == GENERIC);
        Value body = decode_body(rejected);
        CHECK(body.find("message")->text.find(padding) != std::string::npos);
    }
    return 0;
}

}  // namespace

int main() {
    aws_cryptosdk_load_error_strings();

    auto server = new esdk_test_server::http::Server();
    std::string error;
    if (!server->bind(0, &error)) {
        std::fprintf(stderr, "bind failed: %s\n", error.c_str());
        return 1;
    }
    server_port = server->port();
    auto bridge = std::make_shared<esdk_test_server::Bridge>();
    std::thread([server, bridge]() { server->serve_forever(esdk_test_server::make_dispatch(bridge)); }).detach();

    int failures = 0;
    failures += test_round_trip_with_context_and_introspection();
    failures += test_stream_variants_round_trip();
    failures += test_plaintext_length_bound();
    failures += test_bad_protocol_headers_rejected();
    failures += test_unknown_operation_rejected();
    failures += test_malformed_cbor_rejected();
    failures += test_unknown_client_id_rejected();
    failures += test_invalid_configs_rejected();
    failures += test_bad_frame_length_rejected();
    failures += test_esdk_failures_are_client_errors();
    failures += test_reproduced_context_mismatch_rejected();
    failures += test_caching_cmm_round_trip();
    failures += test_raw_rsa_round_trips_per_padding();
    if (failures) {
        std::fprintf(stderr, "%d protocol test(s) failed\n", failures);
        return 1;
    }
    std::printf("all protocol tests passed\n");
    return 0;
}
