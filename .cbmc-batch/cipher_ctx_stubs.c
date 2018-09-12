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

#include <openssl/evp.h>
#include "internal/evp_int.h"

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void){
    EVP_CIPHER_CTX *ctx = malloc(sizeof(EVP_CIPHER_CTX));
    ctx->iv_set = 0;
    ctx->enc_set = 0;
    ctx->freed = 0;
    ctx->all_processed = 0; 
    ctx->padding = 1; 
    ctx->encrypt = -1; 
    return ctx; 
}

int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *ctx)
{
    ctx->iv_set = 0;
    ctx->enc_set = 0;
    ctx->freed = 0;
    ctx->all_processed = 0; 
    ctx->padding = 1; 
    ctx->encrypt = -1; 
    return 1;
}

int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                      ENGINE *impl, const unsigned char *key,
                      const unsigned char *iv, int enc)
{
    // Cipher context cannot be null
    __CPROVER_assert(ctx!=NULL, "EVP_CipherInit_ex: Assertion to ensure that cipher context is not null");
    //The only valid values for enc are 0, 1, -1. 
    __CPROVER_assert(enc==1 || enc==0 || enc==-1, "EVP_CipherInit_ex: Assertion to confirm the enc value provided is valid.");
    //If -1 is specified, encryption or decryption must have already been set. 
    if (enc == -1){
        __CPROVER_assert(ctx->enc_set==1, "EVP_CipherInit_ex: Assertion to confirm if the enc value has been set");
    }
    else {
        ctx->enc_set = 1; 
        if (enc)
            enc = 1;
        ctx->encrypt = enc;
    }
    return 1; 
}


int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    if (type == EVP_CTRL_GCM_SET_IVLEN){
        __CPROVER_assert(ctx->iv_set==0, "EVP_CIPHER_CTX_ctrl: Assertion to confirm that the iv has not been set before its length is specified.");
    }
    if (type == EVP_CTRL_AEAD_GET_TAG){
        __CPROVER_assert(ctx->all_processed==1, "EVP_CIPHER_CTX_ctrl: Assertion to confirm that all data has been processed before getting the tag.");
    }    return 1; 
}


int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl)
{
    __CPROVER_assert(ctx->all_processed==0, "EVP_CipherUpdate: Assertion to confirm that encrypt/decrypt final has not already been called before trying to process more data");
    return 1; 
}

int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl){
    __CPROVER_assert(ctx->all_processed==0, "EVP_DecryptUpdate: Assertion to confirm that decrypt final has not already been called before trying to process more data");
    return 1;
}

int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    __CPROVER_assert(ctx->all_processed==0, "EVP_EncryptUpdate: Assertion to confirm that encrypt final has not already been called before trying to process more data");
    return 1;
}

int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int pad)
{
    if (pad == 0){
        ctx->padding=0;
    }
    __CPROVER_assert(ctx->enc_set==1, "EVP_CIPHER_CTX_set_padding: Assertion to confirm if the enc value has been set before padding is enabled or disabled.");
    return 1;
}

int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    ctx->all_processed=1; 
    return 1;
}

int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    ctx->all_processed=1; 
    return 1;
}

void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)
{  
    ctx->freed =1;
}
