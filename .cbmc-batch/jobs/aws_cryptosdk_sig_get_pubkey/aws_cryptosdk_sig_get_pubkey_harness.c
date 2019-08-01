#include <aws/cryptosdk/cipher.h>
#include <cbmc_invariants.h>
#include <ec_utils.h>
#include <evp_utils.h>
#include <make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>

#include <cipher_openssl.h>

void aws_cryptosdk_sig_get_pubkey_harness() {
    /* arguments */
    struct aws_cryptosdk_sig_ctx *ctx = can_fail_malloc(sizeof(struct aws_cryptosdk_sig_ctx));
    struct aws_allocator *alloc       = can_fail_allocator();
    struct aws_string *pubkey;

    /* assumptions */
    __CPROVER_assume(ctx);
    ensure_sig_ctx_has_allocated_members(ctx);
    __CPROVER_assume(aws_cryptosdk_sig_ctx_is_valid_cbmc(ctx));

    /* operation under verification */
    if (aws_cryptosdk_sig_get_pubkey(ctx, alloc, &pubkey) == AWS_OP_SUCCESS) {
        assert(aws_string_is_valid(pubkey));
    } else {
        assert(!pubkey);
    }

    /* assertions */
    assert(aws_cryptosdk_sig_ctx_is_valid_cbmc(ctx));

    /* clean up */
    EVP_MD_CTX_free(
        ctx->ctx);  // If the EVP_MD_CTX contains a reference to the EVP_PKEY, this decrements the reference count
    evp_pkey_unconditional_free(ctx->pkey);
    ec_key_unconditional_free(ctx->keypair);
    free(ctx);
    free(pubkey);
}
