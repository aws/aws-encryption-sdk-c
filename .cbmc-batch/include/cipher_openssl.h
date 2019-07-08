#include <aws/common/byte_buf.h>
#include <aws/cryptosdk/private/cipher.h>

struct aws_cryptosdk_md_context {
    struct aws_allocator *alloc;
    EVP_MD_CTX *evp_md_ctx;
};
