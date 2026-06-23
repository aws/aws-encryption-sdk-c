#include "test_vectors.h"

EncryptTests ParseEncryptTests(const json &data) {
    EncryptTests tests;
    for (const auto &el : data.items()) {
        tests.push_back(EncryptTest::Parse(el.key(), el.value()));
    }
    return tests;
}

aws_cryptosdk_alg_id GetAlgId(const string &id) {
    if (streq("0578", id)) return ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;
    if (streq("0478", id)) return ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY;
    if (streq("0378", id)) return ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
    if (streq("0346", id)) return ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
    if (streq("0214", id)) return ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256;
    if (streq("0178", id)) return ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256;
    if (streq("0146", id)) return ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256;
    if (streq("0114", id)) return ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256;
    if (streq("0078", id)) return ALG_AES256_GCM_IV12_TAG16_NO_KDF;
    if (streq("0046", id)) return ALG_AES192_GCM_IV12_TAG16_NO_KDF;
    if (streq("0014", id)) return ALG_AES128_GCM_IV12_TAG16_NO_KDF;
    printf("Unknown Alg Id '%s'\n", id.c_str());
    throw("Broken");
}

EncryptTest ParseScenario(const string &name, const json &data);

EncryptTest EncryptTest::Parse(const string &name, const json &data) {
    EncryptTest test;
    bool saw = false;
    for (const auto &el : data.items()) {
        if (streq("encryption-scenario", el.key())) {
            if (saw) {
                printf("Unexpected extra encryption-scenario in %s\n", name.c_str());
            }
            test = ParseScenario(name, el.value());
            saw  = true;
        } else if (streq("decryption-scenario", el.key())) {
            if (saw) {
                printf("Unexpected extra decryption-scenario in %s\n", name.c_str());
            }
            test = ParseScenario(name, el.value());
            saw  = true;
        } else {
            printf("Unexpected element of Encrypt Test : %s\n", el.key().c_str());
            printf("Value : %s\n", string(el.value()).c_str());
        }
    }
    return test;
}

EncryptTest ParseScenario(const string &name, const json &data) {
    EncryptTest test;
    test.name = name;
    for (const auto &el : data.items()) {
        if (streq("type", el.key())) {
            test.type = el.value();
        } else if (streq("algorithmSuiteId", el.key())) {
            test.algorithmSuiteId = el.value();
            test.algId            = GetAlgId(test.algorithmSuiteId);
        } else if (streq("description", el.key())) {
            test.description = el.value();
        } else if (streq("errorDescription", el.key())) {
            test.errorDescription = el.value();
        } else if (streq("decryptErrorDescription", el.key())) {
            test.decryptErrorDescription = el.value();
        } else if (streq("plaintext", el.key())) {
            test.plaintext = el.value();
        } else if (streq("ciphertext", el.key())) {
            test.ciphertext = el.value();
        } else if (streq("result", el.key())) {
            test.result = el.value();
        } else if (streq("frame-size", el.key())) {
            test.frameSize = el.value();
        } else if (streq("encryption-context", el.key())) {
            test.encryptionContext = ParseEC(el.value());
        } else if (streq("reproduced-encryption-context", el.key())) {
            test.reproducedEncryptionContext = ParseEC(el.value());
        } else if (streq("decryptKeyDescription", el.key())) {
            test.decryptKeyDescription = KeyDescription::Parse(el.value());
            test.decryptJson           = el.value();
        } else if (streq("encryptKeyDescription", el.key())) {
            test.encryptKeyDescription = KeyDescription::Parse(el.value());
        } else if (streq("keyDescription", el.key())) {
            test.keyDescription = KeyDescription::Parse(el.value());
        } else {
            printf("Unexpected element of Scenario : %s\n", el.key().c_str());
            printf("Value : %s\n", string(el.value()).c_str());
        }
    }
    return test;
}

DiscoveryFilter DiscoveryFilter::Parse(const json &data) {
    DiscoveryFilter df;
    for (const auto &el : data.items()) {
        if (streq("partition", el.key())) {
            df.partition = el.value();
        } else if (streq("account-ids", el.key())) {
            df.accountIds = ParseStringList(el.value());
        } else {
            printf("Unexpected element of DiscoveryFilter : %s\n", el.key().c_str());
            printf("Value : %s\n", string(el.value()).c_str());
        }
    }
    return df;
}

std::vector<KeyDescription> ParseKeyList(const json &data) {
    std::vector<KeyDescription> keys;
    for (const auto &key : data) {
        keys.push_back(KeyDescription::Parse(key));
    }
    return keys;
}

KeyDescription KeyDescription::Parse(const json &data) {
    KeyDescription kd;
    for (const auto &el : data.items()) {
        if (streq("type", el.key())) {
            kd.type = el.value();
        } else if (streq("sender", el.key())) {
            kd.sender = el.value();
        } else if (streq("recipient", el.key())) {
            kd.recipient = el.value();
        } else if (streq("sender-public-key", el.key())) {
            kd.senderPublicKey = el.value();
        } else if (streq("recipient-public-key", el.key())) {
            kd.recipientPublicKey = el.value();
        } else if (streq("provider-id", el.key())) {
            kd.providerId = el.value();
        } else if (streq("ecc-curve", el.key())) {
            kd.eccCurve = el.value();
        } else if (streq("schema", el.key())) {
            kd.schema = el.value();
        } else if (streq("key", el.key())) {
            kd.key = el.value();
        } else if (streq("encryption-algorithm", el.key())) {
            kd.encryptionAlgorithm = el.value();
        } else if (streq("padding-algorithm", el.key())) {
            kd.paddingAlgorithm = el.value();
        } else if (streq("padding-hash", el.key())) {
            kd.paddingHash = el.value();
        } else if (streq("default-mrk-region", el.key())) {
            kd.defaultMrkRegion = el.value();
        } else if (streq("aws-kms-discovery-filter", el.key())) {
            kd.discoveryFilter = DiscoveryFilter::Parse(el.value());
        } else if (streq("childKeyrings", el.key())) {
            kd.childKeyrings = ParseKeyList(el.value());
        } else if (streq("generator", el.key())) {
            kd.generator.push_back(KeyDescription::Parse(el.value()));
        } else if (streq("underlying", el.key())) {
            kd.underlying.push_back(KeyDescription::Parse(el.value()));
        } else if (streq("requiredEncryptionContextKeys", el.key())) {
            kd.requiredEncryptionContextKeys = ParseStringList(el.value());
        } else {
            printf("Unexpected element of KeyDescription : %s\n", el.key().c_str());
            printf("Value : %s\n", string(el.value()).c_str());
        }
    }
    return kd;
}
