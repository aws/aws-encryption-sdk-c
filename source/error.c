#include <aws/cryptosdk/error.h>

static const struct aws_error_info error_info[] = {
    AWS_DEFINE_ERROR_INFO(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT, AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT, "Bad ciphertext", "cryptosdk")
};

static const struct aws_error_info_list error_info_list = {
    .error_list = error_info,
    .count = sizeof(error_info)/sizeof(error_info[0])
};

void aws_cryptosdk_err_init_strings() {
    aws_register_error_info(&error_info_list);
}
