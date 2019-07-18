#include <aws/cryptosdk/cipher.h>
#include <cbmc_invariants.h>
#include <ec_utils.h>
#include <evp_utils.h>
#include <make_common_data_structures.h>
#include <proof_allocators.h>
#include <proof_helpers/proof_allocators.h>

#include <cipher_openssl.h>

void aws_cryptosdk_sig_verify_finish_harness() {
    /* arguments */
    struct aws_cryptosdk_sig_ctx *ctx = can_fail_malloc(sizeof(struct aws_cryptosdk_sig_ctx));
    struct aws_string *signature      = ensure_string_is_allocated_nondet_length();

    /* assumptions */
    __CPROVER_assume(ctx);
    ensure_sig_ctx_has_allocated_members(ctx);
    __CPROVER_assume(aws_cryptosdk_sig_ctx_is_valid_cbmc(ctx));
    __CPROVER_assume(ctx->alloc);
    __CPROVER_assume(!ctx->is_sign);
    assert(aws_string_is_valid(signature));

    /* saving state */
    EC_KEY *keypair        = ctx->keypair;
    int keypair_references = ec_key_get_reference_count(keypair);
    EVP_PKEY *pkey         = ctx->pkey;
    int pkey_references    = evp_pkey_get_reference_count(pkey);

    /* operation under verification */
    aws_cryptosdk_sig_verify_finish(ctx, signature);

    /* clean up (necessary because we are checking for memory leaks) */
    free(signature);
    if (pkey_references > 2) {
        evp_pkey_unconditional_free(pkey);
        ec_key_unconditional_free(keypair);  // pkey holds a reference to keypair, have to free that as well
    } else if (keypair_references > 2) {     // pkey was freed but keypair was not
        ec_key_unconditional_free(keypair);
    }
}
