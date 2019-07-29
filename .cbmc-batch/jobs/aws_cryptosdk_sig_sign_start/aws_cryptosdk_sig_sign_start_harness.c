#include <aws/cryptosdk/cipher.h>
#include <cbmc_invariants.h>
#include <ec_utils.h>
#include <evp_utils.h>
#include <make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>

#include <cipher_openssl.h>

void aws_cryptosdk_sig_sign_start_harness() {
    /* arguments */
    struct aws_cryptosdk_sig_ctx *ctx;
    struct aws_allocator *alloc = can_fail_allocator();
    struct aws_string *pub_key;
    struct aws_string *priv_key = ensure_string_is_allocated_nondet_length();
    enum aws_cryptosdk_alg_id alg_id;
    struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg_id);

    /* assumptions */
    __CPROVER_assume(props);
    assert(aws_string_is_valid(priv_key));

    bool save_pub_key = nondet_bool();

    /* operation under verification */
    if (aws_cryptosdk_sig_sign_start(
            &ctx, alloc, save_pub_key ? &pub_key : NULL, props, priv_key /* priv_key can't be NULL */) ==
        AWS_OP_SUCCESS) {
        /* assertion: on success, context is initialized unless no curve name was given */
        assert((!props->impl->curve_name && !ctx) || (aws_cryptosdk_sig_ctx_is_valid_cbmc(ctx) && ctx->is_sign));
    }

    /* assertions */
    if (save_pub_key) assert(!pub_key || aws_string_is_valid(pub_key));
    assert(aws_string_is_valid(priv_key));

    /* clean up */
    if (ctx) {
        ec_key_unconditional_free(ctx->keypair);
        evp_pkey_unconditional_free(ctx->pkey);
        evp_md_ctx_shallow_free(ctx->ctx);
    }
    aws_mem_release(alloc, ctx);
    if (save_pub_key) free(pub_key);
    free(priv_key);
}
