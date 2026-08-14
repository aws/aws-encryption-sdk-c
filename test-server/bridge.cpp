/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "bridge.h"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <random>
#include <vector>

#include <aws/common/byte_buf.h>
#include <aws/common/clock.h>
#include <aws/common/common.h>
#include <aws/common/error.h>
#include <aws/common/hash_table.h>
#include <aws/common/string.h>
#include <aws/cryptosdk/cache.h>
#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/header.h>
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/multi_keyring.h>
#include <aws/cryptosdk/raw_aes_keyring.h>
#include <aws/cryptosdk/raw_rsa_keyring.h>
#include <aws/cryptosdk/session.h>

namespace esdk_test_server {

namespace {

struct KeyringDeleter {
    void operator()(struct aws_cryptosdk_keyring *keyring) const {
        aws_cryptosdk_keyring_release(keyring);
    }
};
using KeyringPtr = std::unique_ptr<struct aws_cryptosdk_keyring, KeyringDeleter>;

struct CmmDeleter {
    void operator()(struct aws_cryptosdk_cmm *cmm) const {
        aws_cryptosdk_cmm_release(cmm);
    }
};
using CmmPtr = std::unique_ptr<struct aws_cryptosdk_cmm, CmmDeleter>;

struct CacheDeleter {
    void operator()(struct aws_cryptosdk_materials_cache *cache) const {
        aws_cryptosdk_materials_cache_release(cache);
    }
};
using CachePtr = std::unique_ptr<struct aws_cryptosdk_materials_cache, CacheDeleter>;

struct SessionDeleter {
    void operator()(struct aws_cryptosdk_session *session) const {
        aws_cryptosdk_session_destroy(session);
    }
};
using SessionPtr = std::unique_ptr<struct aws_cryptosdk_session, SessionDeleter>;

struct AwsStringDeleter {
    void operator()(struct aws_string *s) const {
        aws_string_destroy(s);
    }
};
using AwsStringPtr = std::unique_ptr<struct aws_string, AwsStringDeleter>;

struct aws_allocator *alloc() {
    return aws_default_allocator();
}

std::string aws_failure(const char *doing) {
    int error = aws_last_error();
    return std::string(doing) + " failed: " + aws_error_name(error) + ": " + aws_error_str(error);
}

OpError generic(const std::string &message) {
    return OpError(OpError::Kind::Generic, message);
}

OpError esdk(const std::string &message) {
    return OpError(OpError::Kind::Esdk, message);
}

AwsStringPtr make_aws_string(const std::string &s, const char *what) {
    struct aws_string *made = aws_string_new_from_array(alloc(), reinterpret_cast<const uint8_t *>(s.data()), s.size());
    if (!made) throw generic(aws_failure(what));
    return AwsStringPtr(made);
}

/** The single member set on a tagged-union-via-optional-members structure. */
std::pair<std::string, const cbor::Value *> one_variant(
    const cbor::Value &tagged, const std::vector<std::string> &names, const char *what) {
    std::pair<std::string, const cbor::Value *> found("", nullptr);
    size_t count = 0;
    for (const auto &name : names) {
        const cbor::Value *member = tagged.find(name);
        if (member) {
            count++;
            found = std::make_pair(name, member);
        }
    }
    if (count != 1) {
        throw generic(std::string("exactly one ") + what + " variant must be set, found " + std::to_string(count));
    }
    return found;
}

const cbor::Value &require_member(const cbor::Value &shape, const char *member, const char *shape_name) {
    const cbor::Value *value = shape.find(member);
    if (!value) throw generic(std::string(shape_name) + "." + member + " is required");
    return *value;
}

// ---------------------------------------------------------------------------
// Modeled enum mappings.
// ---------------------------------------------------------------------------

enum aws_cryptosdk_commitment_policy map_commitment_policy(const std::string &name) {
    if (name == "FORBID_ENCRYPT_ALLOW_DECRYPT") return COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT;
    if (name == "REQUIRE_ENCRYPT_ALLOW_DECRYPT") return COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT;
    if (name == "REQUIRE_ENCRYPT_REQUIRE_DECRYPT") return COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT;
    throw generic("unknown commitment policy: " + name);
}

struct SuiteMapping {
    const char *name;
    enum aws_cryptosdk_alg_id id;
};

const SuiteMapping SUITES[] = {
    { "ALG_AES_128_GCM_IV12_TAG16_NO_KDF", ALG_AES128_GCM_IV12_TAG16_NO_KDF },
    { "ALG_AES_192_GCM_IV12_TAG16_NO_KDF", ALG_AES192_GCM_IV12_TAG16_NO_KDF },
    { "ALG_AES_256_GCM_IV12_TAG16_NO_KDF", ALG_AES256_GCM_IV12_TAG16_NO_KDF },
    { "ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256", ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256 },
    { "ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256", ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256 },
    { "ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256", ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256 },
    { "ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256", ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 },
    { "ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384", ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 },
    { "ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384", ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 },
    { "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY", ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY },
    { "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384", ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384 },
};

enum aws_cryptosdk_alg_id map_algorithm_suite(const std::string &name) {
    for (const auto &suite : SUITES) {
        if (name == suite.name) return suite.id;
    }
    throw generic("unknown algorithm suite id: " + name);
}

const char *algorithm_suite_name(enum aws_cryptosdk_alg_id id) {
    for (const auto &suite : SUITES) {
        if (suite.id == id) return suite.name;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Keyring construction (tagged union via optional members; recursive Multi).
// ---------------------------------------------------------------------------

const std::vector<std::string> KEYRING_VARIANTS = {
    "AwsKms",
    "AwsKmsMrk",
    "AwsKmsMultiKeyring",
    "AwsKmsMrkMultiKeyring",
    "AwsKmsDiscovery",
    "AwsKmsMrkDiscovery",
    "AwsKmsRsa",
    "RawAes",
    "RawRsa",
    "AwsKmsHierarchical",
    "Multi",
};

KeyringPtr build_keyring(const cbor::Value &config, size_t *edk_bytes_bound);

KeyringPtr build_raw_aes(const cbor::Value &config, size_t *edk_bytes_bound) {
    const std::string &key_namespace = require_member(config, "keyNamespace", "RawAes").as_text("keyNamespace");
    const std::string &key_name      = require_member(config, "keyName", "RawAes").as_text("keyName");
    const std::vector<uint8_t> &key  = require_member(config, "wrappingKey", "RawAes").as_bytes("wrappingKey");
    const std::string &alg           = require_member(config, "wrappingAlg", "RawAes").as_text("wrappingAlg");

    enum aws_cryptosdk_aes_key_len key_len;
    if (alg == "ALG_AES128_GCM_IV12_TAG16") {
        key_len = AWS_CRYPTOSDK_AES128;
    } else if (alg == "ALG_AES192_GCM_IV12_TAG16") {
        key_len = AWS_CRYPTOSDK_AES192;
    } else if (alg == "ALG_AES256_GCM_IV12_TAG16") {
        key_len = AWS_CRYPTOSDK_AES256;
    } else {
        throw generic("unknown AES wrapping algorithm: " + alg);
    }
    if (key.size() != static_cast<size_t>(key_len)) {
        throw generic(
            "wrappingKey must be " + std::to_string(static_cast<size_t>(key_len)) + " bytes for " + alg + ", got " +
            std::to_string(key.size()));
    }

    AwsStringPtr ns   = make_aws_string(key_namespace, "allocate key namespace");
    AwsStringPtr name = make_aws_string(key_name, "allocate key name");
    KeyringPtr keyring(aws_cryptosdk_raw_aes_keyring_new(alloc(), ns.get(), name.get(), key.data(), key_len));
    if (!keyring) throw generic(aws_failure("create raw AES keyring"));
    *edk_bytes_bound += key_namespace.size() + key_name.size() + 1024;
    return keyring;
}

KeyringPtr build_raw_rsa(const cbor::Value &config, size_t *edk_bytes_bound) {
    const std::string &key_namespace = require_member(config, "keyNamespace", "RawRsa").as_text("keyNamespace");
    const std::string &key_name      = require_member(config, "keyName", "RawRsa").as_text("keyName");
    const std::string &padding       = require_member(config, "paddingScheme", "RawRsa").as_text("paddingScheme");

    enum aws_cryptosdk_rsa_padding_mode padding_mode;
    if (padding == "PKCS1") {
        padding_mode = AWS_CRYPTOSDK_RSA_PKCS1;
    } else if (padding == "OAEP_SHA1_MGF1") {
        padding_mode = AWS_CRYPTOSDK_RSA_OAEP_SHA1_MGF1;
    } else if (padding == "OAEP_SHA256_MGF1") {
        padding_mode = AWS_CRYPTOSDK_RSA_OAEP_SHA256_MGF1;
    } else if (padding == "OAEP_SHA384_MGF1" || padding == "OAEP_SHA512_MGF1") {
        throw generic("padding scheme " + padding + " is not supported by the AWS Encryption SDK for C");
    } else {
        throw generic("unknown padding scheme: " + padding);
    }

    // The C constructor takes PEM as NUL-terminated strings.
    const cbor::Value *public_key  = config.find("publicKey");
    const cbor::Value *private_key = config.find("privateKey");
    std::string public_pem, private_pem;
    if (public_key) {
        const std::vector<uint8_t> &bytes = public_key->as_bytes("publicKey");
        public_pem.assign(bytes.begin(), bytes.end());
    }
    if (private_key) {
        const std::vector<uint8_t> &bytes = private_key->as_bytes("privateKey");
        private_pem.assign(bytes.begin(), bytes.end());
    }

    AwsStringPtr ns   = make_aws_string(key_namespace, "allocate key namespace");
    AwsStringPtr name = make_aws_string(key_name, "allocate key name");
    KeyringPtr keyring(aws_cryptosdk_raw_rsa_keyring_new(
        alloc(),
        ns.get(),
        name.get(),
        private_key ? private_pem.c_str() : nullptr,
        public_key ? public_pem.c_str() : nullptr,
        padding_mode));
    if (!keyring) throw generic(aws_failure("create raw RSA keyring"));
    *edk_bytes_bound += key_namespace.size() + key_name.size() + 2048;
    return keyring;
}

KeyringPtr build_multi(const cbor::Value &config, size_t *edk_bytes_bound) {
    const cbor::Value *generator_config = config.find("generator");
    const std::vector<cbor::Value> &child_configs =
        require_member(config, "childKeyrings", "Multi").as_array("childKeyrings");
    if (!generator_config && child_configs.empty()) {
        throw generic("a multi-keyring requires a generator or at least one child keyring");
    }

    KeyringPtr generator;
    if (generator_config) generator = build_keyring(*generator_config, edk_bytes_bound);

    KeyringPtr multi(aws_cryptosdk_multi_keyring_new(alloc(), generator.get()));
    if (!multi) throw generic(aws_failure("create multi-keyring"));

    for (const auto &child_config : child_configs) {
        KeyringPtr child = build_keyring(child_config, edk_bytes_bound);
        if (aws_cryptosdk_multi_keyring_add_child(multi.get(), child.get())) {
            throw generic(aws_failure("add child to multi-keyring"));
        }
    }
    return multi;
}

KeyringPtr build_keyring(const cbor::Value &config, size_t *edk_bytes_bound) {
    std::pair<std::string, const cbor::Value *> variant = one_variant(config, KEYRING_VARIANTS, "keyring");
    if (variant.first == "RawAes") return build_raw_aes(*variant.second, edk_bytes_bound);
    if (variant.first == "RawRsa") return build_raw_rsa(*variant.second, edk_bytes_bound);
    if (variant.first == "Multi") return build_multi(*variant.second, edk_bytes_bound);
    if (variant.first == "AwsKmsHierarchical") {
        throw generic("the AwsKmsHierarchical keyring is not available in the AWS Encryption SDK for C");
    }
    throw generic(
        "the " + variant.first +
        " keyring requires the aws-encryption-sdk-cpp component and is not wired in this test server");
}

// ---------------------------------------------------------------------------
// CMM construction (tagged union; Caching recurses through underlyingCMM).
// ---------------------------------------------------------------------------

const std::vector<std::string> CMM_VARIANTS = { "Default", "RequiredEncryptionContext", "Caching" };

CmmPtr build_cmm_chain(const cbor::Value &config, struct aws_cryptosdk_cmm **inner_default, size_t *edk_bytes_bound) {
    std::pair<std::string, const cbor::Value *> variant = one_variant(config, CMM_VARIANTS, "cmm");

    if (variant.first == "Default") {
        KeyringPtr keyring =
            build_keyring(require_member(*variant.second, "keyring", "DefaultCmmConfig"), edk_bytes_bound);
        CmmPtr cmm(aws_cryptosdk_default_cmm_new(alloc(), keyring.get()));
        if (!cmm) throw generic(aws_failure("create default CMM"));
        *inner_default = cmm.get();
        return cmm;
    }

    if (variant.first == "Caching") {
        const cbor::Value &caching = *variant.second;
        CmmPtr upstream            = build_cmm_chain(
            require_member(caching, "underlyingCMM", "CachingCmmConfig"), inner_default, edk_bytes_bound);

        int64_t ttl_seconds =
            require_member(caching, "cacheLimitTtlSeconds", "CachingCmmConfig").as_int64("cacheLimitTtlSeconds");
        if (ttl_seconds <= 0) throw generic("cacheLimitTtlSeconds must be greater than 0");

        CachePtr cache(aws_cryptosdk_materials_cache_local_new(alloc(), 100));
        if (!cache) throw generic(aws_failure("create local materials cache"));

        const cbor::Value *partition = caching.find("partitionId");
        struct aws_byte_buf partition_buf;
        if (partition) {
            const std::string &text = partition->as_text("partitionId");
            partition_buf = aws_byte_buf_from_array(reinterpret_cast<const uint8_t *>(text.data()), text.size());
        }
        CmmPtr cmm(aws_cryptosdk_caching_cmm_new_from_cmm(
            alloc(),
            cache.get(),
            upstream.get(),
            partition ? &partition_buf : nullptr,
            static_cast<uint64_t>(ttl_seconds),
            AWS_TIMESTAMP_SECS));
        if (!cmm) throw generic(aws_failure("create caching CMM"));

        const cbor::Value *limit_bytes = caching.find("limitBytes");
        if (limit_bytes) {
            int64_t limit = limit_bytes->as_int64("limitBytes");
            if (limit < 0) throw generic("limitBytes must be non-negative");
            if (aws_cryptosdk_caching_cmm_set_limit_bytes(cmm.get(), static_cast<uint64_t>(limit))) {
                throw generic(aws_failure("set caching CMM byte limit"));
            }
        }
        const cbor::Value *limit_messages = caching.find("limitMessages");
        if (limit_messages) {
            int64_t limit = limit_messages->as_int64("limitMessages");
            if (limit <= 0) throw generic("limitMessages must be greater than 0");
            if (aws_cryptosdk_caching_cmm_set_limit_messages(cmm.get(), static_cast<uint64_t>(limit))) {
                throw generic(aws_failure("set caching CMM message limit"));
            }
        }
        return cmm;
    }

    throw generic("the RequiredEncryptionContext CMM is not available in the AWS Encryption SDK for C");
}

std::string make_uuid() {
    uint8_t raw[16];
    int fd      = ::open("/dev/urandom", O_RDONLY);
    bool filled = false;
    if (fd >= 0) {
        filled = ::read(fd, raw, sizeof(raw)) == static_cast<ssize_t>(sizeof(raw));
        ::close(fd);
    }
    if (!filled) {
        std::random_device device;
        for (auto &byte : raw) byte = static_cast<uint8_t>(device());
    }
    raw[6] = static_cast<uint8_t>((raw[6] & 0x0F) | 0x40);
    raw[8] = static_cast<uint8_t>((raw[8] & 0x3F) | 0x80);

    char out[37];
    std::snprintf(
        out,
        sizeof(out),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        raw[0],
        raw[1],
        raw[2],
        raw[3],
        raw[4],
        raw[5],
        raw[6],
        raw[7],
        raw[8],
        raw[9],
        raw[10],
        raw[11],
        raw[12],
        raw[13],
        raw[14],
        raw[15]);
    return std::string(out);
}

// ---------------------------------------------------------------------------
// Request member helpers.
// ---------------------------------------------------------------------------

std::vector<std::pair<std::string, std::string>> read_context_pairs(const cbor::Value *context) {
    std::vector<std::pair<std::string, std::string>> pairs;
    if (!context) return pairs;
    for (const auto &entry : context->as_map("encryptionContext")) {
        pairs.emplace_back(
            entry.first.as_text("encryptionContext key"), entry.second.as_text("encryptionContext value"));
    }
    return pairs;
}

void apply_encryption_context(
    struct aws_cryptosdk_session *session, const std::vector<std::pair<std::string, std::string>> &pairs) {
    if (pairs.empty()) return;
    struct aws_hash_table *table = aws_cryptosdk_session_get_enc_ctx_ptr_mut(session);
    if (!table) throw generic("session encryption context is unavailable");
    for (const auto &pair : pairs) {
        AwsStringPtr key   = make_aws_string(pair.first, "allocate encryption context key");
        AwsStringPtr value = make_aws_string(pair.second, "allocate encryption context value");
        if (aws_hash_table_put(table, key.get(), value.get(), nullptr)) {
            throw generic(aws_failure("apply encryption context"));
        }
        // The table owns both strings now and destroys them with the session.
        key.release();
        value.release();
    }
}

std::vector<std::pair<std::string, std::string>> read_message_context(struct aws_cryptosdk_session *session) {
    std::vector<std::pair<std::string, std::string>> pairs;
    const struct aws_hash_table *table = aws_cryptosdk_session_get_enc_ctx_ptr(session);
    if (!table) return pairs;
    for (struct aws_hash_iter iter = aws_hash_iter_begin(table); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {
        const struct aws_string *key   = static_cast<const struct aws_string *>(iter.element.key);
        const struct aws_string *value = static_cast<const struct aws_string *>(iter.element.value);
        pairs.emplace_back(
            std::string(reinterpret_cast<const char *>(aws_string_bytes(key)), key->len),
            std::string(reinterpret_cast<const char *>(aws_string_bytes(value)), value->len));
    }
    return pairs;
}

const std::vector<uint8_t> &require_blob(const cbor::Value &request, const char *member) {
    const cbor::Value *blob = request.find(member);
    if (!blob) throw generic(std::string(member) + " is required");
    return blob->as_bytes(member);
}

/** Chunk size for driving the streaming session API. */
const size_t STREAM_CHUNK = 4096;

/** A valid pointer for zero-length input: the session rejects null cursors. */
const uint8_t *buffer_ptr(const std::vector<uint8_t> &buffer, size_t offset) {
    static const uint8_t empty = 0;
    return buffer.empty() ? &empty : buffer.data() + offset;
}

std::vector<uint8_t> run_streaming(
    struct aws_cryptosdk_session *session, const std::vector<uint8_t> &input, bool encrypt_mode) {
    const char *doing = encrypt_mode ? "encrypt" : "decrypt";
    std::vector<uint8_t> output;
    size_t out_len          = 0;
    size_t in_off           = 0;
    bool source_drained     = false;
    bool message_size_set   = false;
    unsigned stalled_rounds = 0;

    for (;;) {
        // The session consumes a trailing partial frame only once the message
        // size is known, so declare it as soon as the source is drained (every
        // remaining byte has been offered), not once everything is consumed.
        if (encrypt_mode && !message_size_set && source_drained) {
            if (aws_cryptosdk_session_set_message_size(session, input.size())) {
                throw esdk(aws_failure(doing));
            }
            message_size_set = true;
        }

        size_t out_needed = 0, in_needed = 0;
        aws_cryptosdk_session_estimate_buf(session, &out_needed, &in_needed);
        size_t out_free = std::max(out_needed, STREAM_CHUNK);
        if (output.size() < out_len + out_free) output.resize(out_len + out_free);
        size_t remaining = input.size() - in_off;
        size_t in_give   = std::min(remaining, std::max(in_needed, STREAM_CHUNK));
        if (in_give == remaining) source_drained = true;

        size_t written = 0, read = 0;
        if (aws_cryptosdk_session_process(
                session, output.data() + out_len, out_free, &written, buffer_ptr(input, in_off), in_give, &read)) {
            throw esdk(aws_failure(doing));
        }
        out_len += written;
        in_off += read;

        if (aws_cryptosdk_session_is_done(session)) break;

        if (written == 0 && read == 0) {
            if (!encrypt_mode && in_off == input.size()) {
                throw esdk("decrypt failed: ciphertext ended before the message was complete");
            }
            // One idle round is expected on encrypt between draining the
            // source and declaring the message size.
            if ((!encrypt_mode || message_size_set) && ++stalled_rounds > 2) {
                throw esdk(std::string(doing) + " failed: the session made no progress");
            }
        } else {
            stalled_rounds = 0;
        }
    }

    output.resize(out_len);
    return output;
}

cbor::Value bytes_value(std::vector<uint8_t> bytes) {
    return cbor::Value::make_bytes(std::move(bytes));
}

}  // namespace

/**
 * One registered client. Two shapes:
 * - Default CMM: `keyring` is set; each operation wraps it in a fresh default
 *   CMM so a per-request algorithm-suite override never leaks into the next
 *   request.
 * - Caching CMM: `cmm` is the persistent chain (the cache must survive across
 *   operations) and `inner_default` is the deepest default CMM, where encrypt
 *   pins the algorithm suite per request under `op_mutex`.
 */
struct ClientEntry {
    struct aws_cryptosdk_keyring *keyring                  = nullptr;
    struct aws_cryptosdk_cmm *cmm                          = nullptr;
    struct aws_cryptosdk_cmm *inner_default                = nullptr;
    enum aws_cryptosdk_commitment_policy commitment_policy = COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT;
    size_t max_encrypted_data_keys                         = 0;
    size_t edk_bytes_bound                                 = 0;
    std::mutex op_mutex;

    ~ClientEntry() {
        aws_cryptosdk_cmm_release(cmm);
        aws_cryptosdk_keyring_release(keyring);
    }
};

Bridge::Bridge()  = default;
Bridge::~Bridge() = default;

cbor::Value Bridge::create_client(const cbor::Value &request) {
    const cbor::Value &config = require_member(request, "config", "CreateClientRequest");

    auto entry               = std::make_shared<ClientEntry>();
    entry->commitment_policy = map_commitment_policy(
        require_member(config, "commitmentPolicy", "ESDKClientConfig").as_text("commitmentPolicy"));

    const cbor::Value *max_edks = config.find("maxEncryptedDataKeys");
    if (max_edks) {
        int64_t value = max_edks->as_int64("maxEncryptedDataKeys");
        if (value <= 0) throw generic("maxEncryptedDataKeys must be greater than 0");
        entry->max_encrypted_data_keys = static_cast<size_t>(value);
    }

    const cbor::Value &cmm_config                       = require_member(config, "cmm", "ESDKClientConfig");
    std::pair<std::string, const cbor::Value *> variant = one_variant(cmm_config, CMM_VARIANTS, "cmm");
    if (variant.first == "Default") {
        KeyringPtr keyring =
            build_keyring(require_member(*variant.second, "keyring", "DefaultCmmConfig"), &entry->edk_bytes_bound);
        entry->keyring = keyring.release();
    } else {
        struct aws_cryptosdk_cmm *inner_default = nullptr;
        CmmPtr chain                            = build_cmm_chain(cmm_config, &inner_default, &entry->edk_bytes_bound);
        entry->cmm                              = chain.release();
        entry->inner_default                    = inner_default;
    }

    std::string client_id = make_uuid();
    {
        std::lock_guard<std::mutex> guard(mutex_);
        clients_[client_id] = entry;
    }
    return cbor::Value::make_map({ { cbor::Value::make_text("clientId"), cbor::Value::make_text(client_id) } });
}

std::shared_ptr<ClientEntry> Bridge::resolve(const cbor::Value &request) {
    const cbor::Value *id = request.find("clientId");
    if (!id || id->as_text("clientId").empty()) throw generic("clientId is required and must be non-empty");
    std::lock_guard<std::mutex> guard(mutex_);
    auto found = clients_.find(id->text);
    if (found == clients_.end()) throw generic("unknown clientId: " + id->text);
    return found->second;
}

cbor::Value Bridge::encrypt(const cbor::Value &request, bool streaming) {
    std::shared_ptr<ClientEntry> entry    = resolve(request);
    const std::vector<uint8_t> &plaintext = require_blob(request, "plaintext");
    const cbor::Value *suite              = request.find("algorithmSuiteId");
    const cbor::Value *frame_length       = request.find("frameLength");
    const cbor::Value *plaintext_bound    = streaming ? request.find("plaintextLengthBound") : nullptr;
    auto context_pairs                    = read_context_pairs(request.find("encryptionContext"));
    enum aws_cryptosdk_alg_id requested_alg =
        suite ? map_algorithm_suite(suite->as_text("algorithmSuiteId")) : static_cast<enum aws_cryptosdk_alg_id>(0);

    // Serialize operations on a caching entry: pinning the algorithm suite on
    // the shared inner default CMM is a configuration API, which must not run
    // concurrently with another operation on the same chain.
    std::unique_lock<std::mutex> op_guard;
    CmmPtr fresh_cmm;
    struct aws_cryptosdk_cmm *session_cmm;
    if (entry->cmm) {
        op_guard = std::unique_lock<std::mutex>(entry->op_mutex);
        // Pin explicitly on every request: with no override, use the suite the
        // default CMM would select for the commitment policy, so a previous
        // request's override does not persist.
        enum aws_cryptosdk_alg_id pinned = requested_alg;
        if (!pinned) {
            pinned = aws_cryptosdk_commitment_policy_encrypt_must_include_commitment(entry->commitment_policy)
                         ? ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
                         : ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
        }
        if (aws_cryptosdk_default_cmm_set_alg_id(entry->inner_default, pinned)) {
            throw generic(aws_failure("select algorithm suite"));
        }
        session_cmm = entry->cmm;
    } else {
        fresh_cmm.reset(aws_cryptosdk_default_cmm_new(alloc(), entry->keyring));
        if (!fresh_cmm) throw generic(aws_failure("create default CMM"));
        if (requested_alg && aws_cryptosdk_default_cmm_set_alg_id(fresh_cmm.get(), requested_alg)) {
            throw generic(aws_failure("select algorithm suite"));
        }
        session_cmm = fresh_cmm.get();
    }

    SessionPtr session(aws_cryptosdk_session_new_from_cmm_2(alloc(), AWS_CRYPTOSDK_ENCRYPT, session_cmm));
    if (!session) throw generic(aws_failure("create session"));
    if (aws_cryptosdk_session_set_commitment_policy(session.get(), entry->commitment_policy)) {
        throw generic(aws_failure("set commitment policy"));
    }
    if (entry->max_encrypted_data_keys &&
        aws_cryptosdk_session_set_max_encrypted_data_keys(session.get(), entry->max_encrypted_data_keys)) {
        throw generic(aws_failure("set max encrypted data keys"));
    }

    size_t effective_frame = 256 * 1024;
    if (frame_length) {
        int64_t value = frame_length->as_int64("frameLength");
        if (value <= 0 || value > 0xFFFFFFFFLL) {
            throw esdk("frameLength must be greater than 0 and at most 2^32 - 1, got " + std::to_string(value));
        }
        if (aws_cryptosdk_session_set_frame_size(session.get(), static_cast<uint32_t>(value))) {
            throw esdk(aws_failure("set frame size"));
        }
        effective_frame = static_cast<size_t>(value);
    }

    apply_encryption_context(session.get(), context_pairs);

    std::vector<uint8_t> ciphertext;
    if (streaming) {
        if (plaintext_bound) {
            int64_t bound = plaintext_bound->as_int64("plaintextLengthBound");
            if (bound < 0) throw esdk("plaintextLengthBound must be non-negative");
            if (aws_cryptosdk_session_set_message_bound(session.get(), static_cast<uint64_t>(bound))) {
                throw esdk(aws_failure("set plaintext length bound"));
            }
        }
        ciphertext = run_streaming(session.get(), plaintext, true);
    } else {
        size_t context_bytes = 0;
        for (const auto &pair : context_pairs) context_bytes += pair.first.size() + pair.second.size() + 4;
        size_t frames = plaintext.size() / effective_frame + 2;
        ciphertext.resize(plaintext.size() + entry->edk_bytes_bound + context_bytes + frames * 64 + 2048);

        size_t written = 0;
        if (aws_cryptosdk_session_process_full(
                session.get(),
                ciphertext.data(),
                ciphertext.size(),
                &written,
                buffer_ptr(plaintext, 0),
                plaintext.size())) {
            throw esdk(aws_failure("encrypt"));
        }
        ciphertext.resize(written);
    }

    return cbor::Value::make_map({ { cbor::Value::make_text("ciphertext"), bytes_value(std::move(ciphertext)) } });
}

cbor::Value Bridge::decrypt(const cbor::Value &request, bool streaming) {
    std::shared_ptr<ClientEntry> entry     = resolve(request);
    const std::vector<uint8_t> &ciphertext = require_blob(request, "ciphertext");
    auto reproduced_pairs                  = read_context_pairs(request.find("encryptionContext"));

    CmmPtr fresh_cmm;
    struct aws_cryptosdk_cmm *session_cmm;
    if (entry->cmm) {
        // Decrypt never consults the default CMM's pinned suite, so the
        // persistent chain is shared without the operation lock.
        session_cmm = entry->cmm;
    } else {
        fresh_cmm.reset(aws_cryptosdk_default_cmm_new(alloc(), entry->keyring));
        if (!fresh_cmm) throw generic(aws_failure("create default CMM"));
        session_cmm = fresh_cmm.get();
    }

    SessionPtr session(aws_cryptosdk_session_new_from_cmm_2(alloc(), AWS_CRYPTOSDK_DECRYPT, session_cmm));
    if (!session) throw generic(aws_failure("create session"));
    if (aws_cryptosdk_session_set_commitment_policy(session.get(), entry->commitment_policy)) {
        throw generic(aws_failure("set commitment policy"));
    }
    if (entry->max_encrypted_data_keys &&
        aws_cryptosdk_session_set_max_encrypted_data_keys(session.get(), entry->max_encrypted_data_keys)) {
        throw generic(aws_failure("set max encrypted data keys"));
    }

    std::vector<uint8_t> plaintext;
    if (streaming) {
        plaintext = run_streaming(session.get(), ciphertext, false);
    } else {
        plaintext.resize(ciphertext.size() + 1);
        size_t written = 0;
        if (aws_cryptosdk_session_process_full(
                session.get(),
                plaintext.data(),
                plaintext.size(),
                &written,
                buffer_ptr(ciphertext, 0),
                ciphertext.size())) {
            throw esdk(aws_failure("decrypt"));
        }
        plaintext.resize(written);
    }

    // The optional request context is required to match the encryption context
    // authenticated from the message.
    auto message_context = read_message_context(session.get());
    for (const auto &pair : reproduced_pairs) {
        bool matched = false;
        for (const auto &entry_pair : message_context) {
            if (entry_pair.first == pair.first) {
                if (entry_pair.second != pair.second) {
                    throw esdk("decrypt failed: encryption context value mismatch for key '" + pair.first + "'");
                }
                matched = true;
                break;
            }
        }
        if (!matched) {
            throw esdk("decrypt failed: encryption context key '" + pair.first + "' is not in the message");
        }
    }

    std::vector<std::pair<cbor::Value, cbor::Value>> response;
    response.emplace_back(cbor::Value::make_text("plaintext"), bytes_value(std::move(plaintext)));
    if (!message_context.empty()) {
        std::vector<std::pair<cbor::Value, cbor::Value>> context;
        for (const auto &pair : message_context) {
            context.emplace_back(cbor::Value::make_text(pair.first), cbor::Value::make_text(pair.second));
        }
        response.emplace_back(cbor::Value::make_text("encryptionContext"), cbor::Value::make_map(std::move(context)));
    }
    enum aws_cryptosdk_alg_id alg_id;
    if (!aws_cryptosdk_session_get_alg_id(session.get(), &alg_id)) {
        const char *name = algorithm_suite_name(alg_id);
        if (name) {
            response.emplace_back(cbor::Value::make_text("algorithmSuiteId"), cbor::Value::make_text(name));
        }
    }
    return cbor::Value::make_map(std::move(response));
}

}  // namespace esdk_test_server
