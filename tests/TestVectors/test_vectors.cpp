//#include <aws/core/utils/logging/DefaultLogSystem.h>
#include "test_vectors.h"

int USAGE(const char *s) {
    if (s != nullptr) printf("%s\n", s);
    printf("USAGE :\n");
    printf("run_tests encrypt --manifest-path=arg --decrypt-manifest-path=arg\n");
    printf("run_tests decrypt --manifest-path=arg\n");
    return s != nullptr;
}

int do_encrypt(int argc, char **argv) {
    if (argc != 4 || strcmp(argv[0], "--manifest-path") || strcmp(argv[2], "--decrypt-manifest-path")) {
        printf("USAGE : tv encrypt --manifest-path <path> --decrypt-manifest-path <path>\n");
        return 1;
    }
    auto encrypt_path     = string(argv[1]);
    auto decrypt_path     = string(argv[3]);
    auto decrypt_manifest = decrypt_path + "/decrypt-manifest.json";

    json json_data = read_json("encrypt-manifest.json", encrypt_path);

    json manifest        = json_data.value("manifest"sv, json::object());
    string manifest_type = manifest.value("type"sv, "");
    if (!streq("awses-encrypt", manifest_type)) {
        printf("Encrypt manifest type was '%s' instead of 'awses-encrypt'\n", manifest_type.c_str());
        return 1;
    }
    int manifest_version = manifest.value("version"sv, 0);
    if (manifest_version != 5) {
        printf("Encrypt manifest type was %d instead of 5\n", manifest_version);
        return 1;
    }

    json plaintexts     = json_data.value("plaintexts"sv, json::object());
    auto plaintext_data = MakePlainTexts(plaintexts, decrypt_path);

    string keys_file = json_data.value("keys"sv, "keys.json");
    json keys_data   = read_json(keys_file, encrypt_path);
    json json_keys   = keys_data.value("keys"sv, json::object());
    auto keys        = ParseKeys(json_keys);

    json json_tests = json_data.value("tests"sv, json::object());
    auto tests      = ParseEncryptTests(json_tests);

    TestResults results;
    json decrypt_tests = RunEncryptTests(tests, keys, plaintext_data, results, decrypt_path);
    std::ofstream o(decrypt_manifest);
    o << decrypt_tests << std::endl;
    auto keys_content = read_file(keys_file, encrypt_path);
    write_file(keys_file, keys_content, decrypt_path);

    results.print();
    return 0;
}

int do_decrypt(int argc, char **argv) {
    if (argc != 4 || strcmp(argv[0], "--manifest-path") || strcmp(argv[2], "--manifest-name")) {
        printf("USAGE : tv encrypt --manifest-path <path> --manifest-name <file>\n");
        return 1;
    }
    auto manifest_path = string(argv[1]);
    auto manifest_name = string(argv[3]);

    json json_data = read_json(manifest_name, manifest_path);

    json manifest        = json_data.value("manifest"sv, json::object());
    string manifest_type = manifest.value("type"sv, "");
    if (!streq("awses-decrypt", manifest_type)) {
        printf("Encrypt manifest type was '%s' instead of 'awses-decrypt'\n", manifest_type.c_str());
        return 1;
    }
    int manifest_version = manifest.value("version"sv, 0);
    if (manifest_version != 5) {
        printf("Encrypt manifest type was %d instead of 5\n", manifest_version);
        return 1;
    }

    json keys_file = json_data.value("keys"sv, "keys.json");
    json keys_data = read_json(keys_file, manifest_path);
    json json_keys = keys_data.value("keys"sv, json::object());
    auto keys      = ParseKeys(json_keys);

    json json_tests      = json_data.value("tests"sv, json::object());
    auto tests           = ParseEncryptTests(json_tests);
    auto decrypt_results = RunDecryptTests(tests, keys, manifest_path);
    decrypt_results.print();
    return 0;
}

int main(int argc, char **argv) {
    aws_cryptosdk_load_error_strings();
    Aws::SDKOptions options;
    Aws::InitAPI(options);

    // Aws::Utils::Logging::InitializeAWSLogging(Aws::MakeShared<Aws::Utils::Logging::DefaultLogSystem>(
    //     "Test Vectors", Aws::Utils::Logging::LogLevel(6), "./tvlog_"));

    if (argc < 2) {
        return USAGE("No Function Provided");
        return 1;
    }
    if (strstr(argv[1], "help") != 0) {
        USAGE(nullptr);
        return 0;
    }
    if (strcmp(argv[1], "encrypt") == 0) {
        return do_encrypt(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "decrypt") == 0) {
        return do_decrypt(argc - 2, argv + 2);
    }
    USAGE("Unknown Function");
    return 1;
}
