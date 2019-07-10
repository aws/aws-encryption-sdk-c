#include <aws/cryptosdk/cipher.h>
#include <ec_utils.h>
#include <evp_utils.h>
#include <make_common_data_structures.h>
#include <proof_allocators.h>
#include <proof_helpers/proof_allocators.h>

#include <cipher_openssl.h>

void harness() {
    /* arguments */
    struct aws_cryptosdk_sig_ctx *ctx = can_fail_malloc(sizeof(struct aws_cryptosdk_sig_ctx));
    struct aws_byte_cursor buf;

    /* assumptions */
    __CPROVER_assume(ctx);
    ensure_sig_ctx_has_allocated_members(ctx);
    __CPROVER_assume(ctx->ctx);
    __CPROVER_assume(evp_md_ctx_is_initialized(ctx->ctx));
    ensure_byte_cursor_has_allocated_buffer_member(&buf);
    __CPROVER_assume(buf.ptr);
    size_t old_data_count = evp_md_ctx_data_count(ctx->ctx);
    __CPROVER_assume(old_data_count + buf.len <= EVP_MAX_MD_SIZE);

    /* operation under verification */
    if (aws_cryptosdk_sig_update(ctx, buf) == AWS_OP_SUCCESS) {
        assert(evp_md_ctx_data_count(ctx->ctx) == old_data_count + buf.len);
    } else {
        assert(evp_md_ctx_data_count(ctx->ctx) == old_data_count);
    }

    /* clean up */
    free(buf.ptr);
    ec_key_unconditional_free(ctx->keypair);
    evp_pkey_unconditional_free(ctx->pkey);
    EVP_MD_CTX_free(ctx->ctx);
    free(ctx);
}
