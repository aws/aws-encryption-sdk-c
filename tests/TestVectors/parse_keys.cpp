#include "test_vectors.h"

Bytes decode_base64(const string &input) {
    auto s = base64_decode(input);
    return Bytes(s.begin(), s.end());
}

Key Key::Parse(const json &data) {
    Key key;
    string material;
    for (const auto &el : data.items()) {
        if (streq("type", el.key())) {
            key.type = el.value();
        } else if (streq("key-id", el.key())) {
            key.keyId = el.value();
        } else if (streq("algorithm", el.key())) {
            key.algorithm = el.value();
        } else if (streq("algorithmSuiteId", el.key())) {
            key.algorithmSuiteId = el.value();
            key.algId            = GetAlgId(key.algorithmSuiteId);
        } else if (streq("encrypt", el.key())) {
            key.encrypt = el.value();
        } else if (streq("decrypt", el.key())) {
            key.decrypt = el.value();
        } else if (streq("bits", el.key())) {
            key.bits = el.value();
        } else if (streq("material", el.key())) {
            material = el.value();
        } else if (streq("encoding", el.key())) {
            key.encoding = el.value();
        } else if (streq("public-key-encoding", el.key())) {
            key.publicKeyEncoding = el.value();
        } else if (streq("plaintextDataKey", el.key())) {
            key.plaintextDataKey = decode_base64(el.value());
        } else if (streq("beaconKey", el.key())) {
            key.beaconKey = decode_base64(el.value());
        } else if (streq("branchKey", el.key())) {
            key.branchKey = decode_base64(el.value());
        } else if (streq("encryptedDataKeys", el.key())) {
            key.encryptedDataKeys = ParseEDKs(el.value());
        } else if (streq("recipient-material", el.key())) {
            key.recipientMaterial = el.value();
        } else if (streq("sender-material", el.key())) {
            key.senderMaterial = el.value();
        } else if (streq("recipient-material-public-key", el.key())) {
            key.recipientMaterialPublicKey = el.value();
        } else if (streq("sender-material-public-key", el.key())) {
            key.senderMaterialPublicKey = el.value();
        } else if (streq("branchKeyVersion", el.key())) {
            key.branchKeyVersion = el.value();
        } else if (streq("encryptionContext", el.key())) {
            key.encryptionContext = ParseEC(el.value());
        } else if (streq("requiredEncryptionContextKeys", el.key())) {
            key.requiredEncryptionContextKeys = ParseStringList(el.value());
        } else {
            printf("Unexpected element of Key : %s\n", el.key().c_str());
            printf("Value : %s\n", string(el.value()).c_str());
        }
    }

    if (!material.empty()) {
        if (key.encoding.empty() || streq("base64", key.encoding)) {
            key.material = decode_base64(material);
        } else if (streq("pem", key.encoding)) {
            key.material = Bytes(material.begin(), material.end());
            key.material.push_back(0); // to make it a valid C String
        } else {
            printf("Unknown key encoding : %s\n", key.encoding.c_str());
        }
    }
    return key;
}

KeyMap ParseKeys(const json &data) {
    KeyMap keymap;
    for (const auto &el : data.items()) {
        keymap[el.key()] = Key::Parse(el.value());
    }
    return keymap;
}

EDK EDK::Parse(const json &data) {
    EDK edk;
    for (const auto &el : data.items()) {
        if (streq("keyProviderId", el.key())) {
            edk.keyProviderId = el.value();
        } else if (streq("ciphertext", el.key())) {
            edk.ciphertext = decode_base64(el.value());
        } else if (streq("keyProviderInfo", el.key())) {
            edk.keyProviderInfo = decode_base64(el.value());
        } else {
            printf("Unexpected element of encryptedDataKey : %s\n", el.key().c_str());
        }
    }
    return edk;
}

EDKs ParseEDKs(const json &data) {
    EDKs edks;
    for (const auto &edk : data) {
        edks.push_back(EDK::Parse(edk));
    }
    return edks;
}

RequiredKeys ParseStringList(const json &data) {
    RequiredKeys keys;
    for (const auto &key : data) {
        keys.push_back(key);
    }
    return keys;
}

EncryptionContext ParseEC(const json &data) {
    EncryptionContext ec;
    for (const auto &el : data.items()) {
        ec[el.key()] = el.value();
    }
    return ec;
}
