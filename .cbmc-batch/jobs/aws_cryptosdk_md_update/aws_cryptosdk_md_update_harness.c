#include <aws/cryptosdk/private/cipher.h>
#include <evp_utils.h>
#include <proof_helpers/proof_allocators.h>

#include <cipher_openssl.h>

void harness() {
    /* arguments */
    struct aws_cryptosdk_md_context *md_context = can_fail_malloc(sizeof(struct aws_cryptosdk_md_context));
    size_t length;
    void *buf = bounded_malloc(length);

    /* assumptions */
    __CPROVER_assume(md_context);
    md_context->evp_md_ctx = EVP_MD_CTX_new();
    __CPROVER_assume(md_context->evp_md_ctx);
    evp_md_ctx_nondet_init(md_context->evp_md_ctx);
    assert(evp_md_ctx_is_valid(md_context->evp_md_ctx));
    __CPROVER_assume(buf != NULL);
    size_t data_count = evp_md_ctx_data_count(md_context->evp_md_ctx);
    __CPROVER_assume(data_count + length <= EVP_MAX_MD_SIZE);

    /* operation under verification */
    if (aws_cryptosdk_md_update(md_context, buf, length) == AWS_OP_SUCCESS) {
      assert(evp_md_ctx_data_count(md_context->evp_md_ctx) == data_count + length);
    } else {
      assert(evp_md_ctx_data_count(md_context->evp_md_ctx) == data_count);
    }

    /* assertions */
    assert(aws_cryptosdk_md_context_is_valid(md_context));
    assert(evp_md_ctx_is_initialized(md_context->evp_md_ctx));

    /* clean up */
    EVP_MD_CTX_free(md_context->evp_md_ctx);
    free(md_context);
    free(buf);
}
