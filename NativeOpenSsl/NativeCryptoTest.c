//
//  NativeCryptoTest.c
//  NativeOpenSsl
//
//  Created by Martin Baulig on 12/2/14.
//  Copyright (c) 2014 Martin Baulig. All rights reserved.
//

#include <NativeCryptoTest.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/dh.h>

/* Bits for algorithm2 (handshake digests and other extra flags) */

#define SSL_HANDSHAKE_MAC_MD5 0x10
#define SSL_HANDSHAKE_MAC_SHA 0x20
#define SSL_HANDSHAKE_MAC_GOST94 0x40
#define SSL_HANDSHAKE_MAC_SHA256 0x80
#define SSL_HANDSHAKE_MAC_SHA384 0x100
#define SSL_HANDSHAKE_MAC_DEFAULT (SSL_HANDSHAKE_MAC_MD5 | SSL_HANDSHAKE_MAC_SHA)

/* When adding new digest in the ssl_ciph.c and increment SSM_MD_NUM_IDX
 * make sure to update this constant too */
#define SSL_MAX_DIGEST 6

#define TLS1_PRF_DGST_MASK	(0xff << TLS1_PRF_DGST_SHIFT)

#define TLS1_PRF_DGST_SHIFT 10
#define TLS1_PRF_MD5 (SSL_HANDSHAKE_MAC_MD5 << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_SHA1 (SSL_HANDSHAKE_MAC_SHA << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_SHA256 (SSL_HANDSHAKE_MAC_SHA256 << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_SHA384 (SSL_HANDSHAKE_MAC_SHA384 << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_GOST94 (SSL_HANDSHAKE_MAC_GOST94 << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF (TLS1_PRF_MD5 | TLS1_PRF_SHA1)

#define SSL_MD_MD5_IDX	0
#define SSL_MD_SHA1_IDX	1
#define SSL_MD_GOST94_IDX 2
#define SSL_MD_GOST89MAC_IDX 3
#define SSL_MD_SHA256_IDX 4
#define SSL_MD_SHA384_IDX 5
/*Constant SSL_MAX_DIGEST equal to size of digests array should be
 * defined in the
 * ssl_locl.h */
#define SSL_MD_NUM_IDX	SSL_MAX_DIGEST
static const EVP_MD *ssl_digest_methods[SSL_MD_NUM_IDX]={
	NULL,NULL,NULL,NULL,NULL,NULL
};
/* PKEY_TYPE for GOST89MAC is known in advance, but, because
 * implementation is engine-provided, we'll fill it only if
 * corresponding EVP_PKEY_METHOD is found
 */
static int ssl_mac_secret_size[SSL_MD_NUM_IDX]={
	0,0,0,0,0,0
};

static int ssl_handshake_digest_flag[SSL_MD_NUM_IDX]={
	SSL_HANDSHAKE_MAC_MD5,SSL_HANDSHAKE_MAC_SHA,
	SSL_HANDSHAKE_MAC_GOST94, 0, SSL_HANDSHAKE_MAC_SHA256,
	SSL_HANDSHAKE_MAC_SHA384
};

static int ssl_get_handshake_digest(int idx, long *mask, const EVP_MD **md)
{
	if (idx <0||idx>=SSL_MD_NUM_IDX)
	{
		return 0;
	}
	*mask = ssl_handshake_digest_flag[idx];
	if (*mask)
		*md = ssl_digest_methods[idx];
	else
		*md = NULL;
	return 1;
}

#if DEBUG_FULL
static void
print_buffer(const char *name, const void *buffer, int len)
{
	const unsigned char *ptr = buffer;
	fprintf(stderr, "%s\n", name);
	for(int i = 0; i < len; i++) {
		if ((i % 16) == 0) {
			if (i > 0)
				fprintf(stderr, "\n");
			fprintf(stderr, "    %04x  ", i);
		} else if ((i % 8) == 0) {
			fprintf(stderr, " -");
		}
		fprintf(stderr, " %02x", ptr[i]);
	}
	fprintf(stderr, "\n");
}
#endif

/* seed1 through seed5 are virtually concatenated */
static int
tls1_P_hash(const EVP_MD *md, int compute_mac,
	    const unsigned char *sec, int sec_len,
	    const void *seed1, int seed1_len,
	    const void *seed2, int seed2_len,
	    const void *seed3, int seed3_len,
	    const void *seed4, int seed4_len,
	    const void *seed5, int seed5_len,
	    unsigned char *out, int olen)
{
	int chunk;
	size_t j;
	EVP_MD_CTX ctx, ctx_tmp;
	EVP_PKEY *mac_key;
	unsigned char A1[EVP_MAX_MD_SIZE];
	size_t A1_len;
	int ret = 0;

#if DEBUG_FULL
	fprintf(stderr, "P_HASH\n");
	print_buffer("sec", sec, sec_len);
	if (seed1)
		print_buffer("seed1", seed1, seed1_len);
	if (seed2)
		print_buffer("seed2", seed2, seed2_len);
	if (seed3)
		print_buffer("seed3", seed3, seed3_len);
	if (seed4)
		print_buffer("seed4", seed4, seed4_len);
	if (seed5)
		print_buffer("seed5", seed5, seed5_len);
#endif

	chunk=EVP_MD_size(md);
	OPENSSL_assert(chunk >= 0);

	EVP_MD_CTX_init(&ctx);
	EVP_MD_CTX_init(&ctx_tmp);
	EVP_MD_CTX_set_flags(&ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
	EVP_MD_CTX_set_flags(&ctx_tmp, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
	mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, sec, sec_len);
	if (!mac_key)
		goto err;
	if (!EVP_DigestSignInit(&ctx,NULL,md, NULL, mac_key))
		goto err;
	if (!EVP_DigestSignInit(&ctx_tmp,NULL,md, NULL, mac_key))
		goto err;
	if (seed1 && !EVP_DigestSignUpdate(&ctx,seed1,seed1_len))
		goto err;
	if (seed2 && !EVP_DigestSignUpdate(&ctx,seed2,seed2_len))
		goto err;
	if (seed3 && !EVP_DigestSignUpdate(&ctx,seed3,seed3_len))
		goto err;
	if (seed4 && !EVP_DigestSignUpdate(&ctx,seed4,seed4_len))
		goto err;
	if (seed5 && !EVP_DigestSignUpdate(&ctx,seed5,seed5_len))
		goto err;
	if (!EVP_DigestSignFinal(&ctx,A1,&A1_len))
		goto err;

#if DEBUG_FULL
	fprintf(stderr, "P_HASH #1: %lx\n", A1_len);
	print_buffer("A1", A1, A1_len);
	print_buffer("out", out, olen);
#endif

	if (!compute_mac) {
		if(olen > A1_len)
			return -1;
		memcpy(out, A1, olen);
		ret = 1;
		goto err;
	}

	for (;;)
	{
		/* Reinit mac contexts */
		if (!EVP_DigestSignInit(&ctx,NULL,md, NULL, mac_key))
			goto err;
		if (!EVP_DigestSignInit(&ctx_tmp,NULL,md, NULL, mac_key))
			goto err;
		if (!EVP_DigestSignUpdate(&ctx,A1,A1_len))
			goto err;
		if (!EVP_DigestSignUpdate(&ctx_tmp,A1,A1_len))
			goto err;
		if (seed1 && !EVP_DigestSignUpdate(&ctx,seed1,seed1_len))
			goto err;
		if (seed2 && !EVP_DigestSignUpdate(&ctx,seed2,seed2_len))
			goto err;
		if (seed3 && !EVP_DigestSignUpdate(&ctx,seed3,seed3_len))
			goto err;
		if (seed4 && !EVP_DigestSignUpdate(&ctx,seed4,seed4_len))
			goto err;
		if (seed5 && !EVP_DigestSignUpdate(&ctx,seed5,seed5_len))
			goto err;

		if (olen > chunk)
		{
			if (!EVP_DigestSignFinal(&ctx,out,&j))
				goto err;
			out+=j;
			olen-=j;
			/* calc the next A1 value */
			if (!EVP_DigestSignFinal(&ctx_tmp,A1,&A1_len))
				goto err;
		}
		else	/* last one */
		{
			if (!EVP_DigestSignFinal(&ctx,A1,&A1_len))
				goto err;
			memcpy(out,A1,olen);
			break;
		}
	}
	ret = 1;
err:
	EVP_PKEY_free(mac_key);
	EVP_MD_CTX_cleanup(&ctx);
	EVP_MD_CTX_cleanup(&ctx_tmp);
	OPENSSL_cleanse(A1,sizeof(A1));
	return ret;
}

void
native_crypto_test_init (void)
{
#if DEBUG_FULL
	fprintf(stderr, "NATIVE CRYPTO TEST INIT!\n");
#endif

	EVP_add_cipher(EVP_aes_128_cbc());
	EVP_add_cipher(EVP_aes_192_cbc());
	EVP_add_cipher(EVP_aes_256_cbc());
	EVP_add_cipher(EVP_aes_128_gcm());
	EVP_add_cipher(EVP_aes_256_gcm());
	EVP_add_cipher(EVP_aes_128_cbc_hmac_sha1());
	EVP_add_cipher(EVP_aes_256_cbc_hmac_sha1());

	EVP_add_digest(EVP_md5());
	EVP_add_digest_alias(SN_md5,"ssl2-md5");
	EVP_add_digest_alias(SN_md5,"ssl3-md5");
	EVP_add_digest(EVP_sha1()); /* RSA with sha1 */
	EVP_add_digest_alias(SN_sha1,"ssl3-sha1");
	EVP_add_digest_alias(SN_sha1WithRSAEncryption,SN_sha1WithRSA);
	EVP_add_digest(EVP_sha224());
	EVP_add_digest(EVP_sha256());
	EVP_add_digest(EVP_sha384());
	EVP_add_digest(EVP_sha512());
	EVP_add_digest(EVP_dss1()); /* DSA with sha1 */
	EVP_add_digest_alias(SN_dsaWithSHA1,SN_dsaWithSHA1_2);
	EVP_add_digest_alias(SN_dsaWithSHA1,"DSS1");
	EVP_add_digest_alias(SN_dsaWithSHA1,"dss1");

	ssl_digest_methods[SSL_MD_MD5_IDX]=
	EVP_get_digestbyname(SN_md5);
	ssl_mac_secret_size[SSL_MD_MD5_IDX]=
	EVP_MD_size(ssl_digest_methods[SSL_MD_MD5_IDX]);
	OPENSSL_assert(ssl_mac_secret_size[SSL_MD_MD5_IDX] >= 0);
	ssl_digest_methods[SSL_MD_SHA1_IDX]=
	EVP_get_digestbyname(SN_sha1);
	ssl_mac_secret_size[SSL_MD_SHA1_IDX]=
	EVP_MD_size(ssl_digest_methods[SSL_MD_SHA1_IDX]);
	OPENSSL_assert(ssl_mac_secret_size[SSL_MD_SHA1_IDX] >= 0);
	ssl_digest_methods[SSL_MD_GOST94_IDX]=
	EVP_get_digestbyname(SN_id_GostR3411_94);
	if (ssl_digest_methods[SSL_MD_GOST94_IDX])
	{
		ssl_mac_secret_size[SSL_MD_GOST94_IDX]=
		EVP_MD_size(ssl_digest_methods[SSL_MD_GOST94_IDX]);
		OPENSSL_assert(ssl_mac_secret_size[SSL_MD_GOST94_IDX] >= 0);
	}
	ssl_digest_methods[SSL_MD_GOST89MAC_IDX]=
	EVP_get_digestbyname(SN_id_Gost28147_89_MAC);

	ssl_digest_methods[SSL_MD_SHA256_IDX]=
	EVP_get_digestbyname(SN_sha256);
	ssl_mac_secret_size[SSL_MD_SHA256_IDX]=
	EVP_MD_size(ssl_digest_methods[SSL_MD_SHA256_IDX]);
	ssl_digest_methods[SSL_MD_SHA384_IDX]=
	EVP_get_digestbyname(SN_sha384);
	ssl_mac_secret_size[SSL_MD_SHA384_IDX]=
	EVP_MD_size(ssl_digest_methods[SSL_MD_SHA384_IDX]);
}

static int
get_digest_mask(NativeCryptoHashType type)
{
	switch (type) {
	case NATIVE_CRYPTO_HASH_TYPE_SHA256:
		return TLS1_PRF_SHA256;
	case NATIVE_CRYPTO_HASH_TYPE_SHA384:
		return TLS1_PRF_SHA384;
	default:
		return -1;
	}
}

/* seed1 through seed5 are virtually concatenated */
int
native_crypto_test_PRF(NativeCryptoHashType type,
		       const void *seed1, int seed1_len,
		       const void *seed2, int seed2_len,
		       const void *seed3, int seed3_len,
		       const void *seed4, int seed4_len,
		       const void *seed5, int seed5_len,
		       const unsigned char *sec, int slen,
		       unsigned char *out1,
		       unsigned char *out2, int olen)
{
	int digest_mask;
	int len,i,idx,count;
	const unsigned char *S1;
	long m;
	const EVP_MD *md;
	int ret = 0;

	digest_mask = get_digest_mask(type);
	if (digest_mask < 0)
		return -1;

#if DEBUG_FULL
	fprintf(stderr, "PRF: %x - %p,%x - %p,%x - %p,%x\n", digest_mask, seed1, seed1_len, seed2, seed2_len, sec, slen);
#endif

	/* Count number of digests and partition sec evenly */
	count=0;
	for (idx=0;ssl_get_handshake_digest(idx,&m,&md);idx++) {
		if ((m<<TLS1_PRF_DGST_SHIFT) & digest_mask) count++;
	}
	len=slen/count;
	if (count == 1)
		slen = 0;
#if DEBUG_FULL
	fprintf(stderr, "PRF #1: %x - %x\n", count,len);
#endif
	S1=sec;
	memset(out1,0,olen);
	for (idx=0;ssl_get_handshake_digest(idx,&m,&md);idx++) {
#if DEBUG_FULL
		fprintf(stderr, "PRF #2: %x - %lx\n", idx, m);
#endif
		if ((m<<TLS1_PRF_DGST_SHIFT) & digest_mask) {
			if (!md) {
				goto err;
			}
#if DEBUG_FULL
			fprintf(stderr, "PRF #3a: %x,%x,%x,%x\n", out1[0], out1[1], out1[2], out1[3]);
			fprintf(stderr, "PRF #3b: %x,%x,%x,%x\n", out2[0], out2[1], out2[2], out2[3]);
#endif
			if (!tls1_P_hash(md, 1, S1,len+(slen&1),
					 seed1,seed1_len,seed2,seed2_len,seed3,seed3_len,seed4,seed4_len,seed5,seed5_len,
					 out2,olen))
				goto err;
#if DEBUG_FULL
			fprintf(stderr, "PRF #4: %x,%x,%x,%x\n", out2[0], out2[1], out2[2], out2[3]);
#endif
			S1+=len;
			for (i=0; i<olen; i++)
			{
				out1[i]^=out2[i];
			}
		}
	}
	ret = 1;
#if DEBUG_FULL
	fprintf(stderr, "PRF #5: %x,%x,%x,%x\n", out1[0], out1[1], out1[2], out1[3]);
#endif
err:
	return ret;
}
/* seed1 through seed5 are virtually concatenated */
int
native_crypto_test_HMac(NativeCryptoHashType type,
			const void *seed1, int seed1_len,
			const void *seed2, int seed2_len,
			const void *seed3, int seed3_len,
			const void *seed4, int seed4_len,
			const void *seed5, int seed5_len,
			const unsigned char *sec, int slen,
			unsigned char *out, int olen)
{
	int digest_mask;
	int len,idx,count;
	const unsigned char *S1;
	long m;
	const EVP_MD *md;
	int ret = 0;

	digest_mask = get_digest_mask(type);
	if (digest_mask < 0)
		return -1;

#if DEBUG_FULL
	fprintf(stderr, "HMAC: %x - %p,%x - %p,%x - %p,%x\n", digest_mask, seed1, seed1_len, seed2, seed2_len, sec, slen);
#endif

	/* Count number of digests and partition sec evenly */
	count=0;
	for (idx=0;ssl_get_handshake_digest(idx,&m,&md);idx++) {
		if ((m<<TLS1_PRF_DGST_SHIFT) & digest_mask) count++;
	}
	len=slen/count;
	if (count == 1)
		slen = 0;
#if DEBUG_FULL
	fprintf(stderr, "HMAC #1: %x - %x\n", count,len);
#endif
	S1=sec;
	memset(out,0,olen);
	for (idx=0;ssl_get_handshake_digest(idx,&m,&md);idx++) {
#if DEBUG_FULL
		fprintf(stderr, "HMAC #2: %x - %lx\n", idx, m);
#endif
		if ((m<<TLS1_PRF_DGST_SHIFT) & digest_mask) {
			if (!md) {
				goto err;
			}
#if DEBUG_FULL
			fprintf(stderr, "HMAC #3: %x,%x,%x,%x\n", out[0], out[1], out[2], out[3]);
#endif
			if (!tls1_P_hash(md, 0, S1,len+(slen&1),
					 seed1,seed1_len,seed2,seed2_len,seed3,seed3_len,seed4,seed4_len,seed5,seed5_len,
					 out,olen))
				goto err;
			break;
		}
	}
	ret = 1;
#if DEBUG_FULL
	fprintf(stderr, "HMAC #5: %x,%x,%x,%x\n", out[0], out[1], out[2], out[3]);
#endif
err:
	return ret;
}


/* seed1 through seed5 are virtually concatenated */
static int
tls1_digest(const EVP_MD *md, const void *data, int data_len,
	    unsigned char *out, int olen)
{
	int chunk;
	EVP_MD_CTX ctx;
	unsigned char A1[EVP_MAX_MD_SIZE];
	unsigned int A1_len;
	int ret = 0;

	chunk=EVP_MD_size(md);
	OPENSSL_assert(chunk >= 0);

	EVP_MD_CTX_init(&ctx);
	EVP_MD_CTX_set_flags(&ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
	if (!EVP_DigestInit(&ctx, md))
		goto err;
	if (!EVP_DigestUpdate(&ctx, data, data_len))
		goto err;
	if (!EVP_DigestFinal(&ctx,A1,&A1_len))
		goto err;
	if (A1_len > olen)
		goto err;
	memcpy(out, A1, A1_len);
	return A1_len;

err:
	EVP_MD_CTX_cleanup(&ctx);
	OPENSSL_cleanse(A1,sizeof(A1));
	return ret;
}

int
native_crypto_test_digest(NativeCryptoHashType type, const void *data, int data_len, unsigned char *out, int olen)
{
	int digest_mask;
	int idx,count;
	long m;
	const EVP_MD *md;
	int ret = 0;

	digest_mask = get_digest_mask(type);
	if (digest_mask < 0)
		return -1;

	/* Count number of digests and partition sec evenly */
	count=0;
	for (idx=0;ssl_get_handshake_digest(idx,&m,&md);idx++) {
		if ((m<<TLS1_PRF_DGST_SHIFT) & digest_mask) count++;
	}
	memset(out,0,olen);
	for (idx=0;ssl_get_handshake_digest(idx,&m,&md);idx++) {
		if ((m<<TLS1_PRF_DGST_SHIFT) & digest_mask) {
			if (!md)
				return 0;
			ret = tls1_digest(md, data, data_len, out, olen);
			return ret;
		}
	}

	return 0;
}
