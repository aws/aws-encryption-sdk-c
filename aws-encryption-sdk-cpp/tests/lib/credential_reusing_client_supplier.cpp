/*
 * Copyright (c) 2021 Amazon. All rights reserved.
 */

#include "credential_reusing_client_supplier.h"
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>

namespace Aws {
namespace Cryptosdk {
namespace Testing {

static const char *AWS_CRYPTO_SDK_CRED_CACHING_SUPPLIER = "CredentialCachingClientSupplier";

static std::shared_ptr<KMS::KMSClient> CreateDefaultKmsClient(
    const char *allocationTag,
    const Aws::String &region,
    const std::shared_ptr<Aws::Auth::AWSCredentialsProvider> &credentials_provider) {
    Aws::Client::ClientConfiguration client_configuration;
    if (!region.empty()) {
        client_configuration.region = region;
    }
    client_configuration.userAgent += "sdktesting/kms-keyring-cpp";
#ifdef VALGRIND_TESTS
    // When running under valgrind, the default timeouts are too slow
    client_configuration.requestTimeoutMs = 10000;
    client_configuration.connectTimeoutMs = 10000;
#endif

    return Aws::MakeShared<Aws::KMS::KMSClient>(allocationTag, credentials_provider, client_configuration);
}

CredentialCachingClientSupplier::CredentialCachingClientSupplier()
    : credentials_provider(
          Aws::MakeShared<Aws::Auth::DefaultAWSCredentialsProviderChain>(AWS_CRYPTO_SDK_CRED_CACHING_SUPPLIER)) {}

std::shared_ptr<CredentialCachingClientSupplier> CredentialCachingClientSupplier::Create() {
    return Aws::MakeShared<CredentialCachingClientSupplier>(AWS_CRYPTO_SDK_CRED_CACHING_SUPPLIER);
}

std::shared_ptr<KMS::KMSClient> CredentialCachingClientSupplier::GetClient(
    const Aws::String &region, std::function<void()> &report_success) {
    {
        std::unique_lock<std::mutex> lock(cache_mutex);
        if (cache.find(region) != cache.end()) {
            report_success = [] {};  // no-op lambda
            return cache.at(region);
        }
    }
    auto client    = CreateDefaultKmsClient(AWS_CRYPTO_SDK_CRED_CACHING_SUPPLIER, region, credentials_provider);
    report_success = [this, region, client] {
        std::unique_lock<std::mutex> lock(this->cache_mutex);
        this->cache[region] = client;
    };
    return client;
}
}  // namespace Testing
}  // namespace Cryptosdk
}  // namespace Aws
