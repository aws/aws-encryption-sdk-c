#include "test_vectors.h"

#include <aws/cryptosdk/cpp/kms_keyring.h>
#include <aws/cryptosdk/cpp/kms_mrk_keyring.h>
#include <aws/cryptosdk/multi_keyring.h>
#include <aws/cryptosdk/raw_aes_keyring.h>
#include <aws/cryptosdk/raw_rsa_keyring.h>
#include <aws/cryptosdk/session.h>
#include <unistd.h>

std::shared_ptr<Aws::KMS::KMSClient> create_kms_client(const Aws::String &region) {
    Aws::Client::ClientConfiguration client_config;
    client_config.region = region;
    return Aws::MakeShared<Aws::KMS::KMSClient>("AWS_SAMPLE_CODE", client_config);
}

static Result RunDecryptTest(const EncryptTest &test, aws_cryptosdk_keyring *keyring, const string &dir) {
    if (keyring == nullptr) {
        printf("Failed to make keyring. %s\n", ERROR);
        return Result::Fail;
    }
    auto ciphertext = read_file(test.ciphertext, dir);
    auto plaintext  = read_file(test.result, dir);

    auto plaintext_result       = Bytes(ciphertext.size() + 99999);
    size_t plaintext_result_len = 0;

    auto alloc = aws_default_allocator();

    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_keyring_2(alloc, AWS_CRYPTOSDK_DECRYPT, keyring);
    if (!session) {
        printf("Failed to make session. %s\n", ERROR);
        return Result::Fail;
    }
    aws_cryptosdk_keyring_release(keyring);

    if (aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT)) {
        printf("set_commitment_policy failed: %s", aws_error_debug_str(aws_last_error()));
        return Result::Fail;
    }

    auto code = aws_cryptosdk_session_process_full(
        session,
        &plaintext_result[0],
        plaintext_result.size(),
        &plaintext_result_len,
        &ciphertext[0],
        ciphertext.size());

    if (code != AWS_OP_SUCCESS) {
        printf("Failed to decrypt %d. %s\n", code, ERROR);
        return Result::Fail;
    }
    // if (streq("raw", test.decryptKeyDescription.type)) {
    //     printf("Success : %s\n", test.decryptKeyDescription.key.c_str());
    // }
    aws_cryptosdk_session_destroy(session);
    plaintext_result.resize(plaintext_result_len);

    return (plaintext == plaintext_result) ? Result::Pass : Result::Fail;
}

static aws_cryptosdk_keyring *GetAwsKmsKeyring(const KeyDescription &keydesc, const KeyMap &keys) {
    auto count = keys.count(keydesc.key);
    if (count == 0) {
        printf("Key %s not found.\n", keydesc.key.c_str());
        return nullptr;
    }

    const auto &key = keys.at(keydesc.key);

    return Aws::Cryptosdk::KmsKeyring::Builder().Build(key.keyId);
}

static aws_cryptosdk_keyring *GetAwsKmsMrkKeyring(const KeyDescription &keydesc, const KeyMap &keys) {
    auto count = keys.count(keydesc.key);
    if (count == 0) {
        printf("Key %s not found.\n", keydesc.key.c_str());
        return nullptr;
    }

    const auto &key = keys.at(keydesc.key);
    return Aws::Cryptosdk::KmsMrkAwareSymmetricKeyring::Builder().Build(key.keyId);
}

static aws_cryptosdk_keyring *GetAwsKmsMrkDiscoveryKeyring(const KeyDescription &keydesc, const KeyMap &keys) {
    if (keydesc.discoveryFilter.partition.empty()) {
        return Aws::Cryptosdk::KmsMrkAwareSymmetricKeyring::Builder()
            .WithKmsClient(create_kms_client(Aws::Region::US_WEST_2))
            .BuildDiscovery(keydesc.defaultMrkRegion);
    } else {
        auto builder = Aws::Cryptosdk::KmsKeyring::DiscoveryFilter::Builder(keydesc.discoveryFilter.partition);
        for (const auto &id : keydesc.discoveryFilter.accountIds) {
            builder = builder.AddAccount(id);
        }
        auto filter = builder.Build();
        return Aws::Cryptosdk::KmsMrkAwareSymmetricKeyring::Builder()
            .WithKmsClient(create_kms_client(Aws::Region::US_WEST_2))
            .BuildDiscovery(keydesc.defaultMrkRegion, filter);
    }
}

bool UnsupportedRawKeyring(const KeyDescription &keydesc) {
    auto hash   = keydesc.paddingHash;
    auto alg    = keydesc.encryptionAlgorithm;
    bool is_aes = streq("aes", alg);
    bool is_rsa = streq("rsa", alg);
    if (is_aes) return false;
    if (is_rsa) {
        if (streq("sha384", hash)) {
            return true;
        }
        if (streq("sha512", hash)) {
            return true;
        }
        return false;
    }
    return false;
}

static aws_cryptosdk_keyring *GetRawKeyring(const KeyDescription &keydesc, const KeyMap &keys) {
    auto hash   = keydesc.paddingHash;
    auto e_alg  = keydesc.encryptionAlgorithm;
    auto p_alg  = keydesc.paddingAlgorithm;
    bool is_aes = streq("aes", e_alg);
    bool is_rsa = streq("rsa", e_alg);

    auto count = keys.count(keydesc.key);
    if (count == 0) {
        printf("Key %s not found.\n", keydesc.key.c_str());
        return nullptr;
    }

    const auto &key = keys.at(keydesc.key);
    auto alloc      = aws_default_allocator();

    aws_cryptosdk_keyring *keyring = nullptr;
    auto key_namespace             = aws_string_new_from_c_str(alloc, keydesc.providerId.c_str());
    auto key_name                  = aws_string_new_from_c_str(alloc, key.keyId.c_str());
    if (is_aes) {
        keyring = aws_cryptosdk_raw_aes_keyring_new(
            alloc, key_namespace, key_name, &key.material[0], aws_cryptosdk_aes_key_len(key.material.size()));
    } else if (is_rsa) {
        aws_cryptosdk_rsa_padding_mode mode;
        if (streq("sha1", hash) && streq("pkcs1", p_alg)) {
            mode = AWS_CRYPTOSDK_RSA_PKCS1;
        } else if (streq("sha1", hash) && streq("oaep-mgf1", p_alg)) {
            mode = AWS_CRYPTOSDK_RSA_OAEP_SHA1_MGF1;
        } else if (streq("sha256", hash) && streq("oaep-mgf1", p_alg)) {
            mode = AWS_CRYPTOSDK_RSA_OAEP_SHA256_MGF1;
        } else {
            printf("Unknown rsa padding combo : %s %s\n", hash.c_str(), p_alg.c_str());
            return nullptr;
        }
        bool isPublic = strstr((const char *)&key.material[0], "BEGIN PUBLIC KEY");
        if (isPublic) {
            keyring = aws_cryptosdk_raw_rsa_keyring_new(
                alloc, key_namespace, key_name, nullptr, (const char *)&key.material[0], mode);
        } else {
            keyring = aws_cryptosdk_raw_rsa_keyring_new(
                alloc, key_namespace, key_name, (const char *)&key.material[0], nullptr, mode);
        }
    } else {
        printf("Invalid raw type : %s\n", e_alg.c_str());
        return nullptr;
    }
    aws_string_destroy(key_namespace);
    aws_string_destroy(key_name);
    return keyring;
}

aws_cryptosdk_keyring *GetKeyring(const KeyDescription &keydesc, const KeyMap &keys);

static aws_cryptosdk_keyring *GetMultiKeyring(const KeyDescription &keydesc, const KeyMap &keys) {
    auto alloc     = aws_default_allocator();
    auto generator = GetKeyring(keydesc.generator[0], keys);
    if (generator == nullptr) {
        printf("Failed to make root of multi keyring");
        return nullptr;
    }
    auto multi_keyring = aws_cryptosdk_multi_keyring_new(alloc, generator);
    for (const auto &child : keydesc.childKeyrings) {
        auto child_keyring = GetKeyring(child, keys);
        if (child_keyring == nullptr) {
            printf("Failed to make child keyring");
            return nullptr;
        }
        int res = aws_cryptosdk_multi_keyring_add_child(multi_keyring, child_keyring);
        if (res != AWS_OP_SUCCESS) {
            printf("Failed to add child keyring");
            return nullptr;
        }
    }

    return multi_keyring;
}

aws_cryptosdk_keyring *GetKeyring(const KeyDescription &keydesc, const KeyMap &keys) {
    if (streq("aws-kms", keydesc.type)) {
        return GetAwsKmsKeyring(keydesc, keys);
    } else if (streq("aws-kms-mrk-aware", keydesc.type)) {
        return GetAwsKmsMrkKeyring(keydesc, keys);
    } else if (streq("aws-kms-mrk-aware-discovery", keydesc.type)) {
        return GetAwsKmsMrkDiscoveryKeyring(keydesc, keys);
    } else if (streq("raw", keydesc.type)) {
        return GetRawKeyring(keydesc, keys);
    } else if (streq("multi-keyring", keydesc.type)) {
        return GetMultiKeyring(keydesc, keys);
    } else {
        printf("Unknown Test Type %s\n", keydesc.type.c_str());
        return nullptr;
    }
}

TestResults RunDecryptTests(const EncryptTests &tests, const KeyMap &keys, const string &dir) {
    TestResults res;
    for (const auto &test : tests) {
        res.total++;
        if (streq("required-encryption-context-cmm", test.decryptKeyDescription.type)) {
            res.skipped[RequiredContext]++;
        } else if (streq("aws-kms-hierarchy", test.decryptKeyDescription.type)) {
            res.skipped[HierarchyKeyring]++;
        } else if (streq("aws-kms-rsa", test.decryptKeyDescription.type)) {
            res.skipped[KmsRsa]++;
        } else if (streq("raw-ecdh", test.decryptKeyDescription.type)) {
            res.skipped[Ecdh]++;
        } else if (streq("aws-kms-ecdh", test.decryptKeyDescription.type)) {
            res.skipped[Ecdh]++;
        } else if (UnsupportedRawKeyring(test.decryptKeyDescription)) {
            res.skipped[RsaLongHash]++;
        } else {
            auto keyring = GetKeyring(test.decryptKeyDescription, keys);
            res.bump(RunDecryptTest(test, keyring, dir), test);
        }
    }
    return res;
}

void TestResults::print() const {
    printf("%d tests total\n", total);
    printf("%d tests passed\n", passed);
    printf("%d tests failed\n", failed);
    printf("%d tests skipped for required context\n", skipped[RequiredContext]);
    printf("%d tests skipped for hierarchy keyring\n", skipped[HierarchyKeyring]);
    printf("%d tests skipped for ECDH\n", skipped[Ecdh]);
    printf("%d tests skipped for KMS RSA\n", skipped[KmsRsa]);
    printf("%d tests skipped for RSA long hash\n", skipped[RsaLongHash]);
    if (skipped[NotYet]) printf("%d tests skipped for not yet implemented\n", skipped[NotYet]);
}

Result TestResults::bump(Result result, const EncryptTest &test) {
    switch (result) {
        case Result::Pass: ++passed; break;
        case Result::Fail:
            ++failed;
            printf(
                "Failed Test %s %s %s\n",
                test.name.c_str(),
                test.decryptKeyDescription.type.c_str(),
                test.decryptKeyDescription.encryptionAlgorithm.c_str());
            break;
    }
    return result;
}

Bytes read_file(const std::string &filename, const string &dir) {
    auto name = dir + "/" + (strncmp(filename.c_str(), "file://", 7) ? filename : filename.substr(7));

    std::ifstream file(name, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error(string("Could not open file : ") + name);
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(size);
    if (size > 0) {
        if (!file.read(buffer.data(), size)) {
            throw std::runtime_error("Error while reading file");
        }
    }

    return Bytes(buffer.begin(), buffer.end());
}

json read_json(const string &filename, const string &dir) {
    auto name = dir + "/" + (strncmp(filename.c_str(), "file://", 7) ? filename : filename.substr(7));
    std::ifstream kf(name);
    return json::parse(kf);
}
