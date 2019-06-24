#include <aws/cryptosdk/private/cipher.h>
#include <proof_helpers/proof_allocators.h>

#include <cipher_openssl.h>

void harness() {
    /* arguments */
    struct aws_cryptosdk_md_context *md_context = can_fail_malloc(sizeof(struct aws_cryptosdk_md_context));

    /* assumptions */
    __CPROVER_assume(aws_cryptosdk_md_context_is_valid(md_context));
    md_context->alloc      = can_fail_allocator();
    md_context->evp_md_ctx = EVP_MD_CTX_new();
    __CPROVER_assume(md_context->evp_md_ctx != NULL);

    /* operation under verification */
    aws_cryptosdk_md_abort(md_context);
}
