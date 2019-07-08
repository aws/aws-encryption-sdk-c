#include <aws/cryptosdk/private/cipher.h>
#include <evp_utils.h>
#include <proof_helpers/proof_allocators.h>

#include <cipher_openssl.h>

void harness() {
    /* arguments */
    struct aws_cryptosdk_md_context *md_context = can_fail_malloc(sizeof(struct aws_cryptosdk_md_context));
    size_t buf_size;
    void *buf = bounded_malloc(buf_size);
    size_t length;

    /* assumptions */
    __CPROVER_assume(md_context);
    md_context->alloc = can_fail_allocator();
    md_context->evp_md_ctx = EVP_MD_CTX_new();
    __CPROVER_assume(md_context->evp_md_ctx);
    evp_md_ctx_nondet_init(md_context->evp_md_ctx);
    size_t data_count = evp_md_ctx_data_count(md_context->evp_md_ctx);
    __CPROVER_assume(AWS_MEM_IS_WRITABLE(buf, data_count));

    /* operation under verification */
    if (aws_cryptosdk_md_finish(md_context, buf, &length) == AWS_OP_SUCCESS) {
        assert(length == data_count);
    } else {
        assert(length == 0);
    }
}
