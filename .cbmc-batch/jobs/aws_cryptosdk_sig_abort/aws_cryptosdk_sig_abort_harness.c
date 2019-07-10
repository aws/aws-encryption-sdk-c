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

    /* assumptions */
    if (ctx) {
        ctx->alloc = can_fail_allocator();
        ensure_sig_ctx_has_allocated_members(ctx);
    }

    /* saving previous state */
    EVP_PKEY *keypair               = ctx ? ctx->keypair : NULL;
    int old_keypair_reference_count = ec_key_get_reference_count(keypair);
    EC_KEY *pkey                    = ctx ? ctx->pkey : NULL;
    int old_pkey_reference_count    = evp_pkey_get_reference_count(pkey);

    /* operation under verification */
    aws_cryptosdk_sig_abort(ctx);

    /* assertions */
    if (old_keypair_reference_count > 1) {
        assert(ec_key_get_reference_count(keypair) == old_keypair_reference_count - 1);
        /* clean up */
        ec_key_unconditional_free(keypair);
    }

    if (old_pkey_reference_count > 1) {
        assert(evp_pkey_get_reference_count(pkey) == old_pkey_reference_count - 1);
        /* clean up */
        evp_pkey_unconditional_free(pkey);
    }
}
