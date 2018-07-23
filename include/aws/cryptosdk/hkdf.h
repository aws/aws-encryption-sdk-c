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

#ifndef HKDF_H
#define HKDF_H

#include <openssl/hmac.h>
#include <openssl/evp.h>

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
    unsigned char *prk, unsigned int *prk_len);

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
    unsigned char *okm, int okm_len);

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
	const uint8_t *salt, int salt_len,
	const uint8_t *ikm, int ikm_len, 
	uint8_t *okm, int okm_len,
	const uint8_t *info, int info_len);


#endif
