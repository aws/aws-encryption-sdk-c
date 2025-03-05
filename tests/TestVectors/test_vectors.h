#include <fstream>
#include <string>
#include <string_view>
#include "base64.h"
#include "json.h"

#include <aws/core/Aws.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/session.h>

#include <sys/stat.h>

using json = nlohmann::json;
using namespace std::string_view_literals;
using std::string;

typedef std::vector<uint8_t> Bytes;
Bytes decode_base64(const string &input);
Bytes read_file(const string &filename, const string &dir);
json read_json(const string &filename, const string &dir);
void write_file(const std::string &filename, const Bytes &data, const string &dir);

struct EDK {
    string keyProviderId;
    Bytes keyProviderInfo;
    Bytes ciphertext;
    static EDK Parse(const json &data);
};
typedef std::vector<EDK> EDKs;
EDKs ParseEDKs(const json &data);
typedef std::unordered_map<string, string> EncryptionContext;
EncryptionContext ParseEC(const json &data);
typedef std::vector<string> RequiredKeys;
RequiredKeys ParseStringList(const json &data);

//https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/test-vectors/keys-manifest.md
struct Key {
    string type;
    string keyId;
    string algorithmSuiteId;
    aws_cryptosdk_alg_id algId;
    string algorithm;
    string encoding;
    string publicKeyEncoding;
    string recipientMaterial;
    string senderMaterial;
    string recipientMaterialPublicKey;
    string senderMaterialPublicKey;
    string branchKeyVersion;

    Bytes material;
    Bytes plaintextDataKey;
    Bytes beaconKey;
    Bytes branchKey;

    bool encrypt  = false;
    bool decrypt  = false;
    uint32_t bits = 0;

    EncryptionContext encryptionContext;
    EDKs encryptedDataKeys;
    RequiredKeys requiredEncryptionContextKeys;

    static Key Parse(const json &data);
};

typedef std::unordered_map<string, Key> KeyMap;
KeyMap ParseKeys(const json &data);

inline bool streq(const char *a, const char *b) {
    return strcmp(a, b) == 0;
}

inline bool streq(const char *a, const string &b) {
    return strcmp(a, b.c_str()) == 0;
}

typedef std::vector<string> AccountIDs;
struct DiscoveryFilter {
    string partition;
    AccountIDs accountIds;
    static DiscoveryFilter Parse(const json &data);
};

struct KeyDescription {
    string type;
    string sender;
    string recipient;
    string senderPublicKey;
    string recipientPublicKey;
    string providerId;
    string eccCurve;
    string schema;
    string key;
    string encryptionAlgorithm;
    string paddingAlgorithm;
    string paddingHash;
    string defaultMrkRegion;

    std::vector<KeyDescription> generator;   // never more than one. vector to deal with recursion.
    std::vector<KeyDescription> underlying;  // never more than one. vector to deal with recursion.
    std::vector<KeyDescription> childKeyrings;
    DiscoveryFilter discoveryFilter;
    RequiredKeys requiredEncryptionContextKeys;

    static KeyDescription Parse(const json &data);
};

struct EncryptTest {
    string name;
    string type;
    string description;
    string algorithmSuiteId;
    aws_cryptosdk_alg_id algId;
    string decryptErrorDescription;
    string errorDescription;
    string plaintext;
    string ciphertext;
    string result;

    int frameSize = 0;

    EncryptionContext encryptionContext;
    EncryptionContext reproducedEncryptionContext;
    json reproducedJson = json::object();
    KeyDescription decryptKeyDescription;
    json decryptJson;
    KeyDescription encryptKeyDescription;
    KeyDescription keyDescription;

    static EncryptTest Parse(const string &name, const json &data);
};
typedef std::vector<EncryptTest> EncryptTests;
EncryptTests ParseEncryptTests(const json &data);

enum SkipReasons { RequiredContext, HierarchyKeyring, Ecdh, KmsRsa, RsaLongHash, NotYet, SkipCount };
enum class Result { Pass, Fail };
struct TestResults {
    int total              = 0;
    int passed             = 0;
    int failed             = 0;
    int skipped[SkipCount] = {};
    void print() const;
    Result bump(Result result, const EncryptTest &test);
};
typedef std::unordered_map<string, Bytes> PlainTexts;
PlainTexts MakePlainTexts(const json &plaintexts, const string &dir);
bool UnsupportedRawKeyring(const KeyDescription &keydesc);
TestResults RunDecryptTests(const EncryptTests &tests, const KeyMap &keys, const string &dir);
json RunEncryptTests(
    const EncryptTests &tests,
    const KeyMap &keys,
    const PlainTexts &plaintexts,
    TestResults &results,
    const string &dir);

aws_cryptosdk_keyring *GetKeyring(const KeyDescription &keydesc, const KeyMap &keys);
aws_cryptosdk_alg_id GetAlgId(const string &id);

#define ERROR aws_error_debug_str(aws_last_error())
