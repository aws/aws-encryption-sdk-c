#include "proof_helpers.h"
#include <aws/cryptosdk/private/cipher.h>
#include <openssl/evp.h>

#define MSG_ID_LEN 16

const EVP_MD *nondet_EVP_MD_ptr();
const EVP_CIPHER *nondet_EVP_CIPHER_ptr();

struct aws_cryptosdk_alg_impl {
    const EVP_MD *(*md_ctor)(void);
    const EVP_CIPHER *(*cipher_ctor)(void);
};

const EVP_MD *md_ctor(void) {
    return nondet_EVP_MD_ptr();
}

const EVP_CIPHER *cipher_ctor(void) {
    return nondet_EVP_CIPHER_ptr();
}

void aws_cryptosdk_derive_key_verify(void) {
    struct aws_cryptosdk_alg_properties *props;
    struct content_key *content_key;
    struct data_key *data_key;
    uint8_t *message_id;
    ASSUME_VALID_MEMORY(props);
    props->impl = malloc(sizeof(&md_ctor) + sizeof(&cipher_ctor));

    props->impl->md_ctor = NULL;
    props->impl->cipher_ctor = NULL;
    if (nondet_int())
        props->impl->md_ctor = &md_ctor;
    if (nondet_int())
        props->impl->cipher_ctor = &cipher_ctor;

    __CPROVER_assume(props->data_key_len <= MAX_DATA_KEY_SIZE);

    ASSUME_VALID_MEMORY(content_key);
    ASSUME_VALID_MEMORY(data_key);
    ASSUME_VALID_MEMORY_COUNT(message_id, MSG_ID_LEN);

    aws_cryptosdk_derive_key(props, content_key, data_key, message_id);
}
