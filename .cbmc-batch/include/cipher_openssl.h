#include <aws/cryptosdk/private/cipher.h>

struct aws_cryptosdk_sig_ctx {
  struct aws_allocator *alloc;
  const struct aws_cryptosdk_alg_properties *props;
  EC_KEY *keypair;
  EVP_PKEY *pkey;
  EVP_MD_CTX *ctx;
  bool is_sign;
};

struct aws_cryptosdk_md_context {
    struct aws_allocator *alloc;
    EVP_MD_CTX *evp_md_ctx;
};
