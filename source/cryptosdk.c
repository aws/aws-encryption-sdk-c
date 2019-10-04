#include <aws/common/common.h>

#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/cryptosdk.h>

static bool crypto_sdk_initialized = false;

void aws_cryptosdk_init(struct aws_allocator *allocator) {
    (void)allocator;
    if (!crypto_sdk_initialized) {
        crypto_sdk_initialized = true;
        //aws_common_library_init(allocator);
        aws_cryptosdk_register_error_info();
    }
}

void aws_cryptosdk_clean_up(void) {
    if (crypto_sdk_initialized) {
        crypto_sdk_initialized = false;
        aws_cryptosdk_unregister_error_info();
        //aws_common_library_clean_up();
    }
}
