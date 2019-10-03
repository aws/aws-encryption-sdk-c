#ifndef AWS_CRYPTOSDK_CRYPTOSDK_H
#define AWS_CRYPTOSDK_CRYPTOSDK_H

#include <aws/common/common.h>
#include <aws/cryptosdk/exports.h>

#ifdef __cplusplus
extern "C" {
#endif

AWS_CRYPTOSDK_API
void aws_cryptosdk_init(struct aws_allocator *allocator);

AWS_CRYPTOSDK_API
void aws_cryptosdk_clean_up(void);

#ifdef __cplusplus
}
#endif

#endif
