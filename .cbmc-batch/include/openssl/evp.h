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

const EVP_CIPHER *EVP_aes_128_gcm(void);
const EVP_CIPHER *EVP_aes_192_gcm(void);
const EVP_CIPHER *EVP_aes_256_gcm(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);

# define         EVP_CTRL_INIT                   0x0
# define         EVP_CTRL_SET_KEY_LENGTH         0x1
# define         EVP_CTRL_GET_RC2_KEY_BITS       0x2
# define         EVP_CTRL_SET_RC2_KEY_BITS       0x3
# define         EVP_CTRL_GET_RC5_ROUNDS         0x4
# define         EVP_CTRL_SET_RC5_ROUNDS         0x5
# define         EVP_CTRL_RAND_KEY               0x6
# define         EVP_CTRL_PBE_PRF_NID            0x7
# define         EVP_CTRL_COPY                   0x8
# define         EVP_CTRL_AEAD_SET_IVLEN         0x9
# define         EVP_CTRL_AEAD_GET_TAG           0x10
# define         EVP_CTRL_AEAD_SET_TAG           0x11
# define         EVP_CTRL_AEAD_SET_IV_FIXED      0x12
# define         EVP_CTRL_GCM_SET_IVLEN          EVP_CTRL_AEAD_SET_IVLEN
# define         EVP_CTRL_GCM_GET_TAG            EVP_CTRL_AEAD_GET_TAG
# define         EVP_CTRL_GCM_SET_TAG            EVP_CTRL_AEAD_SET_TAG
# define         EVP_CTRL_GCM_SET_IV_FIXED       EVP_CTRL_AEAD_SET_IV_FIXED
# define         EVP_CTRL_GCM_IV_GEN             0x13
# define         EVP_CTRL_CCM_SET_IVLEN          EVP_CTRL_AEAD_SET_IVLEN
# define         EVP_CTRL_CCM_GET_TAG            EVP_CTRL_AEAD_GET_TAG
# define         EVP_CTRL_CCM_SET_TAG            EVP_CTRL_AEAD_SET_TAG
# define         EVP_CTRL_CCM_SET_IV_FIXED       EVP_CTRL_AEAD_SET_IV_FIXED
# define         EVP_CTRL_CCM_SET_L              0x14
# define         EVP_CTRL_CCM_SET_MSGLEN         0x15
