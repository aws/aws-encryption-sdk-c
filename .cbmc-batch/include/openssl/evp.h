#include <stddef.h>

#include <openssl/ossl_typ.h>

void EVP_PKEY_free(EVP_PKEY *pkey);
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
const EVP_MD *EVP_sha512();

#define EVP_MD_CTX_create()     EVP_MD_CTX_new()
#define EVP_MD_CTX_destroy(ctx) EVP_MD_CTX_free((ctx))
