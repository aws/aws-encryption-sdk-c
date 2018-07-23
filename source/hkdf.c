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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "aws/cryptosdk/hkdf.h"


/*
 *  hkdfExtract()
 *
 * 	Description: This function will perform the HKDF extraction. This function takes in an
 *				 input keying material and extracts from a psuedo random key (prk). 
 *  Parameters:
 *      evp_md : EVP_MD for SHA1, SHA224, SHA256, SHA384, SHA512 algorithms.
 *      salt: optional salt value (a non-secret random value);
 *             if not provided, it is set to a string of HashLen zeros.
 *      salt_len: The length of the salt value.
 *      ikm: Input keying material.
 *      ikm_len: The length of the input keying material.
 *      prk: The pseudo random key extracted from the ikm. 
 *
 *  Returns:
 *      Status Code
 *
 */
int hkdfExtract(const EVP_MD *evp_md,
    const unsigned char *salt, int salt_len,
    const unsigned char *ikm, int ikm_len,
    unsigned char *prk, unsigned int *prk_len){
	if(salt == NULL){
		salt_len = EVP_MD_size(evp_md); 
		memset((void *)salt, '\0', salt_len);
	}
	if (HMAC(evp_md, ikm, ikm_len, salt, salt_len, prk, prk_len) == NULL)
		return 0;
	else
		return 1;
}

/*
 *  hkdfExpand()
 *
 * 	Description: This function will perform the HKDF extraction. This function takes in an
 *				 input keying material and extracts from a psuedo random key (prk). 
 *  Parameters:
 *		evp_md: EVP_MD for SHA1, SHA224, SHA256, SHA384, SHA512 algorithms. 
 *		prk : The pseudo random key extracted from the ikm. 
 * 		prk_len: The length of the pseudo random key. 
 *      info: Optional information about the application.
 *      info_len: The length of the information. 
 *      okm: Output keying material. Where the HKDF result is obtained.
 *      okm_len: The length of the output keying material.
 *     
 *  Returns:
 *      Status Code
 *
 */
int hkdfExpand(const EVP_MD *evp_md, 
	const unsigned char *prk, int prk_len,
    const unsigned char *info, int info_len,
    unsigned char *okm, int okm_len)
{
  HMAC_CTX ctx; 
  unsigned char T[EVP_MAX_MD_SIZE];
  unsigned char temp[EVP_MAX_MD_SIZE];
  int N, counter, i; 
  int *T_len=NULL; 


  if (prk_len < 0 || info_len < 0 || okm != NULL || okm_len <= 0)
  	  return 0; 

  if(prk == NULL)
   	return 0; 

  if(info == NULL){
	 info_len = 0; 
	 memset((void *)info,'\0', info_len);
  }

  HMAC_CTX_init(&ctx);
  if (!HMAC_Init_ex(&ctx, prk, prk_len, evp_md, NULL))
  	return 0; 
  
  N = okm_len/ EVP_MD_size(evp_md); 
  if (!okm_len % EVP_MD_size(evp_md))
  	N+=1;

  *T_len = 0;
  counter = 0; 

  for (i = 1; i <= N; i++) {
  	if(!HMAC_Update(&ctx, T, *T_len))
  		return 0;

  	if(!HMAC_Update(&ctx, info, info_len))
  		return 0;

  	if(!HMAC_Update(&ctx, (const unsigned char *) &counter, 1))
  		return 0;


  	if(!HMAC_Final(&ctx, temp, (unsigned int *)T_len))
  		return 0; 

  	memcpy(T, temp, *T_len);
  	counter += 1; 

  }
  memcpy(okm, T, okm_len);
  HMAC_CTX_cleanup(&ctx);
  return 1;
}

/*
 *  hkdf() 
 * 
 *  Description:
 *		HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
 *      This function will call hkdfExtract() and hkdfExpand()
 *
 *  Parameters:
 *      evp_md: EVP_MD for SHA1, SHA224, SHA256, SHA384, SHA512 algorithms. 
 *      salt: optional salt value (a non-secret random value);
 *            if not provided, it is set to a string of HashLen zeros.
 *      salt_len: The length of the salt value.
 *      ikm: Input keying material.
 *      ikm_len: The length of the input keying material.
 *      info: Optional information about the application.
 *      info_len: The length of the information. 
 *      okm: Output keying material. Where the HKDF result is obtained.
 *      okm_len: The length of the output keying material. 
 *
 *  Returns:
 *      Status code 
 */

int hkdf(const EVP_MD *evp_md,
	const unsigned char *salt, int salt_len,
	const unsigned char *ikm, int ikm_len, 
	uint8_t *okm, int okm_len,
	const unsigned char *info, int info_len){

	unsigned char prk[EVP_MAX_MD_SIZE]; 
	unsigned int *prk_len=NULL; 
	return hkdfExtract(evp_md, salt, salt_len, ikm, ikm_len, prk, prk_len) || 
	hkdfExpand(evp_md, prk, (int)*prk_len, info, info_len, okm, okm_len);
}


