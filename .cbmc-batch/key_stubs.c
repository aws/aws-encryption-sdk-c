/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*Stubs of OpenSSL functions pertaining to key derivation */

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "internal/evp_int.h"


int EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX *pctx, unsigned char *info, int infolen){

    __CPROVER_assert(pctx->initialized==1, "EVP_PKEY_CTX_add1_hkdf_info Assertion to confirm if the public key algorithm context has been initialized before setting info.");

    int len = pctx->infolen;
    __CPROVER_assert(len +infolen < 1024, "EVP_PKEY_CTX_add1_hkdf_info: Assert to ensure that the infolen value is never more than 1024");
    pctx->infolen=len+infolen;
    len = pctx->infolen;

    return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_INFO, infolen, (void *)(info));

}

int EVP_PKEY_CTX_set1_hkdf_salt(EVP_PKEY_CTX *pctx, unsigned char *salt, int saltlen){
     __CPROVER_assert(pctx->initialized==1, "EVP_PKEY_CTX_set1_hkdf_salt SALT: Assertion to confirm if the public key algorithm context has been initialized before setting salt.");

    pctx->salt = 1;

    return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_SALT, saltlen, (void *)(salt));
}

int EVP_PKEY_CTX_set_hkdf_md(EVP_PKEY_CTX *pctx, const EVP_MD *md){
     __CPROVER_assert(pctx->initialized==1, "EVP_PKEY_CTX_set_hkdf_md: Assertion to confirm if the public key algorithm context has been initialized before setting message digest.");

    pctx->md=1;    

    return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_MD, 0, (void *)(md));

}

int EVP_PKEY_CTX_set1_hkdf_key(EVP_PKEY_CTX *pctx, unsigned char *key,
                                int keylen){
     __CPROVER_assert(pctx->initialized==1, "PARAMETER KEY: Assertion to confirm if the public key algorithm context has been initialized before setting the key.");
     pctx->key=1;

    return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_KEY, keylen, (void *)(key));

 }

int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *pkeylen)
{
    if (ctx->hkdf) {
        // If the mode uses an expand operation, passing a NULL buffer is not meaningful.
        if (ctx->hkdf_mode==0 || ctx->hkdf_mode== 2){
            __CPROVER_assert(key!=NULL, "KEY DERIVATION: Assertion to confirm that key buffer is not NULL in an HKDF mode that uses extract");
        }
        // In this mode the digest, key, salt and info values must be set before a key is derived or an error occurs.
        __CPROVER_assert(ctx->md==1, "KEY DERIVATION: Assertion to confirm that the digest is set");
        __CPROVER_assert(ctx->key==1, "KEY DERIVATION: Assertion to confirm that the key is set");
        if (ctx->hkdf_mode==0||ctx->hkdf_mode==1){
            __CPROVER_assert(ctx->salt==1, "KEY DERIVATION: Assertion to confirm that the salt is set");
        }
        if (ctx->hkdf_mode==0||ctx->hkdf_mode==2){
            __CPROVER_assert(ctx->infolen>0, "KEY DERIVATION: Assertion to confirm that the info is set");
        }

    }
    return 1;
}



EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e)
{
    EVP_PKEY_CTX *pctx = int_ctx_new(NULL, e, id);
    pctx->initialized=0;
    pctx->md=0;
    pctx->key=0;
    pctx->infolen=0;
    pctx->salt=0;
    pctx->hkdf=0;

    // NID_hkdf is 1036. If this is used as the id, mark the HKDF as used. 
    if (id==1036){
        pctx->hkdf=1;
        // Set the mode to default mode: EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND
        pctx->hkdf_mode=0;
    }
  

    return pctx;
}

int EVP_PKEY_CTX_hkdf_mode(EVP_PKEY_CTX *pctx, int mode){
    pctx->hkdf_mode=mode;
    return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_MODE, mode, NULL);
}


 int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx){
    ctx->initialized=1;
    return 1; 
 }

