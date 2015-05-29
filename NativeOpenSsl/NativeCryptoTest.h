//
//  NativeCryptoTest.h
//  NativeOpenSsl
//
//  Created by Martin Baulig on 12/2/14.
//  Copyright (c) 2014 Martin Baulig. All rights reserved.
//

#ifndef __NativeOpenSsl__NativeCryptoTest__
#define __NativeOpenSsl__NativeCryptoTest__

#include <stdio.h>

typedef enum {
	NATIVE_CRYPTO_HASH_TYPE_SHA256,
	NATIVE_CRYPTO_HASH_TYPE_SHA384
} NativeCryptoHashType;

void
native_crypto_test_init (void);

int
native_crypto_test_PRF (NativeCryptoHashType type,
			const void *seed1, int seed1_len,
			const void *seed2, int seed2_len,
			const void *seed3, int seed3_len,
			const void *seed4, int seed4_len,
			const void *seed5, int seed5_len,
			const unsigned char *sec, int slen,
			unsigned char *out1,
			unsigned char *out2, int olen);

int
native_crypto_test_HMac (NativeCryptoHashType type,
			 const void *seed1, int seed1_len,
			 const void *seed2, int seed2_len,
			 const void *seed3, int seed3_len,
			 const void *seed4, int seed4_len,
			 const void *seed5, int seed5_len,
			 const unsigned char *sec, int slen,
			 unsigned char *out, int olen);

int
native_crypto_test_digest (NativeCryptoHashType type, const void *data, int data_len,
			   unsigned char *out, int olen);

#endif /* defined(__NativeOpenSsl__NativeCryptoTest__) */
