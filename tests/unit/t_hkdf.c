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
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "testing.h"
#include <string.h>
#include <aws/cryptosdk/hkdf.h>


void test_hkdf_case1(){
    const unsigned char salt[] = "0x000102030405060708090a0b0c";
    int salt_len = 13; 
    const unsigned char ikm[] = "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    int ikm_len = 22; 
	unsigned char okm[42*8]; 
	int okm_len = 42; 
	const unsigned char info[] = "0xf0f1f2f3f4f5f6f7f8f9";
	int info_len = 10; 

	unsigned char prk[EVP_MAX_MD_SIZE]; 
	unsigned int *prk_len=NULL; 

	if(hkdfExtract(EVP_sha256(), salt, salt_len, ikm, ikm_len, prk, prk_len) == 0){
		printf("Error occured in the hkdfExtract function");
		return;
	} 

	if(strcmp("0x077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",(const char*)prk) != 0){
		printf("PRK incorrect for TestCase1");
		return; 
	}

	if(hkdfExpand(EVP_sha256(), prk, *prk_len, info, info_len, okm, okm_len) == 0){
		printf("Error occured in the hkdfExpand function");
		return;
	}

	if(strcmp("0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", (const char*)okm) != 0){
		printf("OKM incorrect for TestCase1");
		return; 
	}

	printf("TestCase1 Passed");

}




void test_hkdf_case2(){
    const unsigned char salt[] = "0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
    int salt_len = 80; 
    const unsigned char ikm[] = "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f";
    int ikm_len = 80; 
	unsigned char okm[82*8];
	int okm_len = 82; 
	const unsigned char info[] = "0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
	int info_len = 10; 

	unsigned char prk[EVP_MAX_MD_SIZE]; 
	unsigned int *prk_len = NULL; 

	if(hkdfExtract(EVP_sha256(), salt, salt_len, ikm, ikm_len, prk, prk_len) == 0){
		printf("Error occured in the hkdfExtract function");
		return;
	} 

	if(strcmp("0x06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",(const char*)prk) != 0){
		printf("PRK incorrect for TestCase2");
		return; 
	}

	if(hkdfExpand(EVP_sha256(), prk, *prk_len, info, info_len, okm, okm_len) == 0){
		printf("Error occured in the hkdfExpand function");
		return;
	}

	if(strcmp("0xb11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87", (const char*)okm) != 0){
		printf("OKM incorrect for TestCase1");
		return; 
	}

	printf("TestCase2 Passed");

}

void test_hkdf_case3(){
    const unsigned char salt[] = "";
    int salt_len = 0; 
    const unsigned char ikm[] = "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    int ikm_len = 22; 
    unsigned char okm[42*8];
	int okm_len = 42; 
	const unsigned char info[] = "";
	int info_len = 0; 

	unsigned char prk[EVP_MAX_MD_SIZE]; 
	unsigned int *prk_len=NULL; 

	if(hkdfExtract(EVP_sha256(), salt, salt_len, ikm, ikm_len, prk, prk_len) == 0){
		printf("Error occured in the hkdfExtract function");
		return;
	} 

	if(strcmp("0x19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",(const char*)prk) != 0){
		printf("PRK incorrect for TestCase2");
		return; 
	}

	if(hkdfExpand(EVP_sha256(), prk, *prk_len, info, info_len, okm,okm_len) == 0){
		printf("Error occured in the hkdfExpand function");
		return;
	}

	if(strcmp("0x8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", (const char*)okm) != 0){
		printf("OKM incorrect for TestCase1");
		return; 
	}

	printf("TestCase3 Passed");

}

int main(){
	test_hkdf_case1();
	test_hkdf_case2();
	test_hkdf_case3();
	retun 0;
}





