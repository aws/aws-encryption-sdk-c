#include <aws/cryptosdk/private/cipher.h>
#include <evp_utils.h>
#include <proof_helpers/make_common_data_structures.h>

#include <cipher_openssl.h>

void harness() {
    /* arguments */
    struct aws_allocator *alloc;
    struct aws_cryptosdk_md_context *md_context;
    enum aws_cryptosdk_md_alg md_alg;

    /* assumptions */
    alloc = can_fail_allocator();

    /* operation under verification */
    if (aws_cryptosdk_md_init(alloc, &md_context, md_alg) == AWS_OP_SUCCESS) {
        /* assertions */
        assert(aws_cryptosdk_md_context_is_valid(md_context));
        assert(evp_md_ctx_is_initialized(md_context->evp_md_ctx));
    }

    /* clean up */
    if (md_context) {
        EVP_MD_CTX_free(md_context->evp_md_ctx);
        aws_mem_release(alloc, md_context);
    }
}
