/*
 * Copyright (c) 2021 Amazon. All rights reserved.
 */

#pragma once

#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/cryptosdk/cpp/kms_keyring.h>
#include <memory>
#include <mutex>

#include "exports.h"

namespace Aws {
namespace Cryptosdk {
namespace Testing {

class TESTLIB_CPP_API CredentialCachingClientSupplier : public KmsKeyring::ClientSupplier {
   public:
    /**
     * Helper function which creates a new CachingClientSupplier and returns a shared pointer to it.
     */
    static std::shared_ptr<CredentialCachingClientSupplier> Create();

    /**
     * If @param region is the empty string, then returns a KMS client in the SDK's default region.
     * If a client is already cached for this region, returns that one and provides a no-op callable.
     * If a client is not already cached for this region, returns a KMS client with default settings
     * and provides a callable which will cache the client. Never returns nullptr.
     */
    std::shared_ptr<Aws::KMS::KMSClient> GetClient(const Aws::String &region, std::function<void()> &report_success);

    CredentialCachingClientSupplier();
    virtual ~CredentialCachingClientSupplier() = default;

   protected:
    mutable std::mutex cache_mutex;
    std::shared_ptr<Aws::Auth::AWSCredentialsProvider> credentials_provider;
    /**
     * Region -> KMS Client.
     */
    Aws::Map<Aws::String, std::shared_ptr<Aws::KMS::KMSClient>> cache;
};
}  // namespace Testing
}  // namespace Cryptosdk
}  // namespace Aws
