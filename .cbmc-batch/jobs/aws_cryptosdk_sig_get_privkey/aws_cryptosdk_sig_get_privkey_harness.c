#include <aws/cryptosdk/cipher.h>
#include <cbmc_invariants.h>
#include <ec_utils.h>
#include <evp_utils.h>
#include <make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>

#include <cipher_openssl.h>

void aws_cryptosdk_sig_get_privkey_harness() {
    /* arguments */
    struct aws_cryptosdk_sig_ctx *ctx = can_fail_malloc(sizeof(struct aws_cryptosdk_sig_ctx));
    struct aws_allocator *alloc       = can_fail_allocator();
    struct aws_string *priv_key;

    /* assumptions */
    __CPROVER_assume(ctx);
    ensure_sig_ctx_has_allocated_members(ctx);
    __CPROVER_assume(aws_cryptosdk_sig_ctx_is_valid_cbmc(ctx));
    __CPROVER_assume(ctx->is_sign);  // context has to be in signing mode, otherwise private key is NULL

    /* operation under verification */
    if (aws_cryptosdk_sig_get_privkey(ctx, alloc, &priv_key) == AWS_OP_SUCCESS) {
        assert(aws_string_is_valid(priv_key));
    } else {
        assert(!priv_key);
    }

    /* assertions */
    assert(aws_cryptosdk_sig_ctx_is_valid_cbmc(ctx));

    /* clean up */
    EVP_MD_CTX_free(ctx->ctx);
    evp_pkey_unconditional_free(ctx->pkey);
    ec_key_unconditional_free(ctx->keypair);
    free(ctx);
    free(priv_key);
}
