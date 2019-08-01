#include <aws/cryptosdk/cipher.h>
#include <cbmc_invariants.h>
#include <ec_utils.h>
#include <evp_utils.h>
#include <make_common_data_structures.h>
#include <proof_allocators.h>
#include <proof_helpers/proof_allocators.h>

#include <cipher_openssl.h>

void aws_cryptosdk_sig_sign_start_keygen_harness() {
    /* arguments */
    struct aws_cryptosdk_sig_ctx *pctx;
    struct aws_allocator *alloc = can_fail_allocator();
    struct aws_string *pub_key;
    enum aws_cryptosdk_alg_id alg_id;
    struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg_id);

    /* assumptions */
    __CPROVER_assume(props);

    bool save_pub_key = nondet_bool();

    /* operation under verification */
    if (aws_cryptosdk_sig_sign_start_keygen(&pctx, alloc, save_pub_key ? &pub_key : NULL, props) == AWS_OP_SUCCESS) {
        assert((!props->impl->curve_name && !pctx) || (aws_cryptosdk_sig_ctx_is_valid_cbmc(pctx) && pctx->is_sign));
    }

    /* assertions */
    if (save_pub_key) assert(!pub_key || aws_string_is_valid(pub_key));

    /* clean up */
    if (pctx) {
        ec_key_unconditional_free(pctx->keypair);
        evp_pkey_unconditional_free(pctx->pkey);
        evp_md_ctx_shallow_free(pctx->ctx);
    }
    aws_mem_release(alloc, pctx);
    if (save_pub_key) free(pub_key);
}
