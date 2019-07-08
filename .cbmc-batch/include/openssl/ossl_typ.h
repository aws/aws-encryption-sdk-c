#ifdef NO_ASN1_TYPEDEFS
#define ASN1_INTEGER            ASN1_STRING
#else
typedef struct asn1_string_st ASN1_INTEGER;
#endif

#ifdef BIGNUM
#undef BIGNUM
#endif
typedef struct bio_st BIO;
typedef struct bignum_st BIGNUM;

typedef struct ec_key_st EC_KEY;

typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_md_st EVP_MD;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct evp_pkey_st EVP_PKEY;

typedef struct engine_st ENGINE;
