#include <aws/cryptosdk/default_cmm.h>
#include "test_vectors.h"

bool aws_cryptosdk_algorithm_is_committing(uint16_t alg_id) {
    switch (alg_id) {
        case ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY:
        case ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384: return true;
        default: return false;
    }
}

void AddCtx(struct aws_cryptosdk_session *session, const EncryptionContext &ctx) {
    if (ctx.empty()) return;

    auto session_ctx = aws_cryptosdk_session_get_enc_ctx_ptr_mut(session);
    if (!session_ctx) {
        printf("failed to get encryption context from session\n");
        abort();
    }
    auto alloc = aws_default_allocator();

    for (const auto &pair : ctx) {
        auto key   = aws_string_new_from_c_str(alloc, pair.first.c_str());
        auto value = aws_string_new_from_c_str(alloc, pair.second.c_str());
        int was_created;
        if (AWS_OP_SUCCESS != aws_hash_table_put(session_ctx, key, (void *)value, &was_created)) {
            printf("failed to add to encryption context\n");
            abort();
        }
        if (was_created != 1) {
            printf("impossible duplicate in encryption context\n");
            abort();
        }
    }
}

Bytes GenRandom(uint32_t size) {
    Bytes b;
    b.reserve(size);
    while (b.size() < size) {
        uint32_t x           = random();
        const uint8_t *bytes = (const uint8_t *)&x;
        b.insert(b.end(), bytes, bytes + sizeof(x));
    }
    b.resize(size);
    return b;
}

void write_file(const std::string &filename, const Bytes &data, const string &dir) {
    auto name = dir + "/" + (strncmp(filename.c_str(), "file://", 7) ? filename : filename.substr(7));
    std::ofstream file(name, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error(string("Error while opening file for writing : ") + name);
    }
    if (!file.write((const char *)data.data(), data.size())) {
        throw std::runtime_error(string("Error while writing file : ") + name);
    }
}

PlainTexts MakePlainTexts(const json &plaintexts, const string &dir) {
    mkdir((dir + "/plaintexts").c_str(), 0777);
    PlainTexts p;
    for (const auto &el : plaintexts.items()) {
        uint32_t size = el.value();
        Bytes bytes   = GenRandom(size);
        p[el.key()]   = bytes;
        auto filename = string("plaintexts/") + el.key();
        write_file(filename, bytes, dir);
    }
    return p;
}

json MakeDecryptJson(const EncryptTest &test, const Bytes &ciphertext_result, const string &dir) {
    string outname = string("ciphertexts/") + test.name;
    write_file(outname, ciphertext_result, dir);
    json inner = { { "type", test.type },
                   { "result", string("file://plaintexts/") + test.plaintext },
                   { "ciphertext", string("file://") + outname },
                   { "algorithmSuiteId", test.algorithmSuiteId },
                   { "frame-size", test.frameSize },
                   { "decryptKeyDescription", test.decryptJson },
                   { "reproduced-encryption-context", test.reproducedJson },
                   { "description", test.description } };
    json outer = { { "decryption-scenario", inner } };
    return outer;
}

static json RunEncryptTest(
    const EncryptTest &test,
    aws_cryptosdk_cmm *cmm,
    const PlainTexts &plaintexts,
    TestResults &results,
    const string &dir) {
    if (cmm == nullptr) {
        printf("Failed to make keyring. %s\n", ERROR);
        return results.bump(Result::Fail, test);
    }
    if (AWS_OP_SUCCESS != aws_cryptosdk_default_cmm_set_alg_id(cmm, test.algId)) {
        printf("failed to set algorithm ID: %s %s", test.algorithmSuiteId.c_str(), ERROR);
        return results.bump(Result::Fail, test);
    }

    const Bytes &plaintext = plaintexts.at(test.plaintext);

    auto ciphertext_result       = Bytes(plaintext.size() + 99999);
    size_t ciphertext_result_len = 0;

    auto alloc = aws_default_allocator();

    struct aws_cryptosdk_session *session = aws_cryptosdk_session_new_from_cmm_2(alloc, AWS_CRYPTOSDK_ENCRYPT, cmm);
    if (!session) {
        printf("Failed to make session. %s\n", ERROR);
        return results.bump(Result::Fail, test);
    }
    aws_cryptosdk_cmm_release(cmm);

    AddCtx(session, test.encryptionContext);

    bool alg_committing                    = aws_cryptosdk_algorithm_is_committing(test.algId);
    aws_cryptosdk_commitment_policy policy = alg_committing ? COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT
                                                            : COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT;

    if (aws_cryptosdk_session_set_commitment_policy(session, policy)) {
        printf("set_commitment_policy failed: %s", ERROR);
        return results.bump(Result::Fail, test);
    }

    if (test.frameSize > 0) {
        if (aws_cryptosdk_session_set_frame_size(session, test.frameSize)) {
            printf("Failed to set frame size to %d : %s", test.frameSize, ERROR);
            return results.bump(Result::Fail, test);
        }
    }
    auto code = aws_cryptosdk_session_process_full(
        session,
        &ciphertext_result[0],
        ciphertext_result.size(),
        &ciphertext_result_len,
        &plaintext[0],
        plaintext.size());

    if (code != AWS_OP_SUCCESS) {
        printf("Failed to encrypt: %d %s\n", code, ERROR);
        return results.bump(Result::Fail, test);
    }
    aws_cryptosdk_session_destroy(session);
    ciphertext_result.resize(ciphertext_result_len);
    results.bump(Result::Pass, test);
    return MakeDecryptJson(test, ciphertext_result, dir);
}

static json RunEncryptTestK(
    const EncryptTest &test,
    aws_cryptosdk_keyring *keyring,
    const PlainTexts &plaintexts,
    TestResults &results,
    const string &dir) {
    if (keyring == nullptr) {
        printf("Failed to make keyring. %s\n", ERROR);
        return results.bump(Result::Fail, test);
    }
    auto cmm = aws_cryptosdk_default_cmm_new(aws_default_allocator(), keyring);
    aws_cryptosdk_keyring_release(keyring);
    return RunEncryptTest(test, cmm, plaintexts, results, dir);
}

json RunEncryptTests(
    const EncryptTests &tests,
    const KeyMap &keys,
    const PlainTexts &plaintexts,
    TestResults &results,
    const string &dir) {
    mkdir((dir + "/ciphertexts").c_str(), 0777);
    json manifest = {
        { "type", "awses-decrypt" },
        { "version", 5 },
    };
    json client = {
        { "name", "aws-encryption-sdk-c" },
        { "version", "2.4.1" },
    };
    json out_tests = json::object();

    for (const auto &test : tests) {
        results.total++;
        if (streq("required-encryption-context-cmm", test.encryptKeyDescription.type)) {
            results.skipped[RequiredContext]++;
        } else if (streq("aws-kms-hierarchy", test.encryptKeyDescription.type)) {
            results.skipped[HierarchyKeyring]++;
        } else if (streq("aws-kms-rsa", test.encryptKeyDescription.type)) {
            results.skipped[KmsRsa]++;
        } else if (streq("raw-ecdh", test.encryptKeyDescription.type)) {
            results.skipped[Ecdh]++;
        } else if (streq("aws-kms-ecdh", test.encryptKeyDescription.type)) {
            results.skipped[Ecdh]++;
        } else if (UnsupportedRawKeyring(test.encryptKeyDescription)) {
            results.skipped[RsaLongHash]++;
        } else {
            auto keyring  = GetKeyring(test.encryptKeyDescription, keys);
            auto one_test = RunEncryptTestK(test, keyring, plaintexts, results, dir);
            if (one_test.is_object()) {
                out_tests[test.name] = one_test;
            }
        }
    }

    json result = {
        { "manifest", manifest },
        { "client", client },
        { "keys", "file://keys.json" },
        { "tests", out_tests },
    };
    return result;
}
