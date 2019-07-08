#include <openssl/evp.h>

void evp_pkey_nondet_init(EVP_PKEY* pkey);

int evp_pkey_get_reference_count(EVP_PKEY* pkey);

void evp_pkey_unconditional_free(EVP_PKEY* pkey);

bool evp_md_ctx_is_valid(EVP_MD_CTX *ctx);

bool evp_md_ctx_is_initialized(EVP_MD_CTX *ctx);

size_t evp_md_ctx_data_count(EVP_MD_CTX *ctx);

void evp_md_ctx_nondet_init(EVP_MD_CTX *ctx);
