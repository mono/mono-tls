//
//  NativeOpenSsl.c
//  NativeOpenSsl
//
//  Created by Martin Baulig on 27/11/14.
//  Copyright (c) 2014 Xamarin. All rights reserved.
//

#include <NativeOpenSsl.h>
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

static int
init_client (unsigned char ip[4], int port)
{
	int s, ret;
	struct sockaddr_in addr;
	unsigned long ipaddr;

	s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s < 0)
		return -1;
	
	memset ((char*)&addr, 0, sizeof (addr));
	addr.sin_port = htons (port);
	addr.sin_family = AF_INET;
	ipaddr = (unsigned long)
	((unsigned long)ip[0]<<24L)|((unsigned long)ip[1]<<16L)|
	((unsigned long)ip[2]<< 8L)|((unsigned long)ip[3]);
	addr.sin_addr.s_addr = htonl(ipaddr);
	
	ret = connect (s, (struct sockaddr *)&addr, sizeof (addr));
	if (ret < 0)
		return -1;
	
	return s;
}

static int
init_server (unsigned char ip[4], int port)
{
	int s, ret;
	struct sockaddr_in addr;
	unsigned long ipaddr;
	int value = 1;
	
	s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s < 0)
		return -1;
	
	setsockopt (s, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));
	
	memset ((char*)&addr, 0, sizeof (addr));
	addr.sin_port = htons (port);
	addr.sin_family = AF_INET;
	ipaddr = (unsigned long)
	((unsigned long)ip[0]<<24L)|((unsigned long)ip[1]<<16L)|
	((unsigned long)ip[2]<< 8L)|((unsigned long)ip[3]);
	addr.sin_addr.s_addr = htonl (ipaddr);
	
	ret = bind (s, (struct sockaddr *)&addr, sizeof (addr));
	if (ret < 0)
		return -1;
	
	ret = listen (s, 1);
	if (ret < 0)
		return -1;
	
	return s;
}

static unsigned char dh512_p[] = {
	0xDA, 0x58, 0x3C, 0x16, 0xD9, 0x85, 0x22, 0x89, 0xD0, 0xE4, 0xAF, 0x75,
	0x6F, 0x4C, 0xCA, 0x92, 0xDD, 0x4B, 0xE5, 0x33, 0xB8, 0x04, 0xFB, 0x0F,
	0xED, 0x94, 0xEF, 0x9C, 0x8A, 0x44, 0x03, 0xED, 0x57, 0x46, 0x50, 0xD3,
	0x69, 0x99, 0xDB, 0x29, 0xD7, 0x76, 0x27, 0x6B, 0xA2, 0xD3, 0xD4, 0x12,
	0xE2, 0x18, 0xF4, 0xDD, 0x1E, 0x08, 0x4C, 0xF6, 0xD8, 0x00, 0x3E, 0x7C,
	0x47, 0x74, 0xE8, 0x33,
};
static unsigned char dh512_g[] = {
	0x02,
};

static DH *
get_dh512 (void)
{
	DH *dh = NULL;

	if ((dh=DH_new ()) == NULL) return NULL;
	dh->p = BN_bin2bn (dh512_p, sizeof(dh512_p), NULL);
	dh->g = BN_bin2bn (dh512_g, sizeof(dh512_g), NULL);
	if (!dh->p || !dh->g)
		return NULL;
	return dh;
}

int
native_openssl_shutdown (NativeOpenSsl *ptr)
{
	return SSL_shutdown(ptr->ssl);
}

void
native_openssl_destroy (NativeOpenSsl *ptr)
{
	if (ptr->ssl) {
		SSL_free (ptr->ssl);
		ptr->ssl = NULL;
	}
	if (ptr->ctx) {
		SSL_CTX_free (ptr->ctx);
		ptr->ctx = NULL;
	}
	if (ptr->socket > 0) {
		close (ptr->socket);
		ptr->socket = 0;
	}
	free (ptr);
}

static long
dump_callback (BIO *bio, int cmd, const char *argp, int argi, long argl, long ret)
{
	NativeOpenSsl *ptr;
	
	ptr = (NativeOpenSsl*)BIO_get_callback_arg (bio);
	if (!ptr || !ptr->debug_callback) return ret;
	
	if (cmd == (BIO_CB_READ|BIO_CB_RETURN))
		ptr->debug_callback (cmd, argp, argi, ret);
	else if (cmd == (BIO_CB_WRITE|BIO_CB_RETURN))
		ptr->debug_callback (cmd, argp, argi, ret);
	return ret;
}

static void
message_callback (int write_p, int version, int content_type, const void *buf,
		  size_t len, SSL *ssl, void *arg)
{
	NativeOpenSsl *ptr = (NativeOpenSsl*)arg;
	if (ptr->message_callback)
		ptr->message_callback (write_p, version, content_type, buf, len);
}

static void
native_openssl_init_fd (NativeOpenSsl *ptr, int s)
{
	ptr->sbio = BIO_new_socket (s, BIO_NOCLOSE);
	SSL_set_bio (ptr->ssl, ptr->sbio, ptr->sbio);
	
	if (ptr->debug_callback) {
		SSL_set_debug (ptr->ssl, 1);
		BIO_set_callback (ptr->sbio, dump_callback);
		BIO_set_callback_arg (ptr->sbio, (char *)ptr);
	}
	
	if (ptr->message_callback) {
		SSL_set_msg_callback (ptr->ssl, message_callback);
		SSL_set_msg_callback_arg (ptr->ssl, (char*)ptr);
	}
}

NativeOpenSsl *
native_openssl_initialize (int debug, DebugCallback debug_callback, MessageCallback message_callback)
{
	NativeOpenSsl *ptr;

	SSL_library_init ();
	
	ptr = calloc (1, sizeof (NativeOpenSsl));
	ptr->debug = debug;
	ptr->debug_callback = debug_callback;
	ptr->message_callback = message_callback;
	return ptr;
}

static void
native_openssl_error (NativeOpenSsl *ptr, const char *message)
{
	if (!ptr->debug)
		return;

	BIO *bio_err;
	bio_err = BIO_new_fp (stderr, BIO_NOCLOSE);
	printf ("ERROR: %s\n", message);
	ERR_print_errors (bio_err);
}

int
native_openssl_connect (NativeOpenSsl *ptr, unsigned char ip[4], int port)
{
	int ret, s;
	
	s = init_client (ip, port);
	if (s < 0) {
		fprintf (stderr, "Connect failed: %d (%s)\n", errno, strerror(errno));
		return NATIVE_OPENSSL_ERROR_SOCKET;
	}
	
	ptr->socket = s;
	
	native_openssl_init_fd (ptr, s);
	
	ret = SSL_connect (ptr->ssl);
	if (ret != 1) {
		native_openssl_error (ptr, "Connect failed");
		return NATIVE_OPENSSL_ERROR_SSL_CONNECT;
	}
	
	return 0;
}

int
native_openssl_write (NativeOpenSsl *ptr, const void *buf, int offset, int size)
{
	return SSL_write (ptr->ssl, buf + offset, size);
}

int
native_openssl_read (NativeOpenSsl *ptr, void *buf, int offset, int size)
{
	return SSL_read (ptr->ssl, buf + offset, size);
}

int
native_openssl_bind (NativeOpenSsl *ptr, unsigned char ip[4], int port)
{
	int s;
	
	s = init_server (ip, port);
	if (s < 0) {
		fprintf (stderr, "Bind failed: %d (%s)\n", errno, strerror(errno));
		return NATIVE_OPENSSL_ERROR_SOCKET;
	}
	
	ptr->socket = s;
	return 0;
}

int
native_openssl_accept (NativeOpenSsl *ptr)
{
	struct sockaddr_in addr;
	socklen_t len;
	int ret, s;

	s = accept (ptr->socket, (struct sockaddr *)&addr, &len);
	if (s < 0) {
		fprintf (stderr, "Accept failed: %d (%s)\n", errno, strerror(errno));
		return NATIVE_OPENSSL_ERROR_SOCKET;
	}
	
	ptr->accepted = s;
	
	native_openssl_init_fd (ptr, s);
	
	ret = SSL_accept (ptr->ssl);
	if (ret <= 0) {
		native_openssl_error(ptr, "Accept failed");
		return NATIVE_OPENSSL_ERROR_SSL_ACCEPT;
	}
	
	return 0;
}

int
native_openssl_load_certificate_from_pkcs12 (NativeOpenSsl *ptr, const void *buf, int len,
					     const char *password, int passlen,
					     X509 **out_certificate, EVP_PKEY **out_private_key)
{
	BIO *bio;
	PKCS12 *p12;

	bio = BIO_new_mem_buf ((void *)buf, len);
	p12 = d2i_PKCS12_bio (bio, NULL);
	if (!p12) {
		native_openssl_error (ptr, "Error loading PKCS12 certificate.");
		BIO_free (bio);
		return NATIVE_OPENSSL_ERROR_PKCS12_LOAD;
	}

	if (!PKCS12_verify_mac (p12, password, passlen)) {
		native_openssl_error (ptr, "Error loading PKCS12 certificate (MAC verify error).");
		PKCS12_free (p12);
		BIO_free (bio);
		return NATIVE_OPENSSL_ERROR_PKCS12_VERIFY;
	}

	if (!PKCS12_parse (p12, password, out_private_key, out_certificate, NULL)) {
		native_openssl_error(ptr, "Error loading PKCS12 certificate (Parse failed).");
		PKCS12_free (p12);
		BIO_free (bio);
		return NATIVE_OPENSSL_ERROR_PKCS12_PARSE;
	}

	PKCS12_free (p12);
	BIO_free (bio);
	return 0;
}

X509 *
native_openssl_load_certificate_from_pem (NativeOpenSsl *ptr, const void *buf, int len)
{
	BIO *bio;
	X509 *cert;
 
	bio = BIO_new_mem_buf ((void *)buf, len);
	cert = PEM_read_bio_X509 (bio, NULL, NULL, NULL);
	BIO_free (bio);
	return cert;
}

EVP_PKEY *
native_openssl_load_private_key_from_pem (NativeOpenSsl *ptr, const void *buf, int len)
{
	BIO *bio;
	EVP_PKEY *pkey;
	
	bio = BIO_new_mem_buf ((void *)buf, len);
	pkey = PEM_read_bio_PrivateKey (bio,NULL, NULL, NULL);
	BIO_free (bio);
	return pkey;
}

X509 *
native_openssl_load_certificate_from_file (NativeOpenSsl *ptr, const char *filename)
{
	BIO *bio;
	X509 *cert;

	bio = BIO_new_file (filename, "r");
	cert = PEM_read_bio_X509 (bio, NULL, NULL, NULL);
	BIO_free (bio);
	return cert;
}

EVP_PKEY *
native_openssl_load_private_key_from_file (NativeOpenSsl *ptr, const char *filename)
{
	BIO *bio;
	EVP_PKEY *pkey;
 
	bio = BIO_new_file (filename, "r");
	pkey = PEM_read_bio_PrivateKey (bio,NULL, NULL, NULL);
	BIO_free (bio);
	return pkey;
}

int
native_openssl_set_certificate (NativeOpenSsl *ptr, X509 *certificate, EVP_PKEY *private_key)
{
	if (SSL_CTX_use_certificate (ptr->ctx, certificate) <= 0) {
		native_openssl_error(ptr, "Error setting certificate");
		return NATIVE_OPENSSL_ERROR_INVALID_CERT;
	}
	
	if (SSL_CTX_use_PrivateKey (ptr->ctx, private_key) <= 0) {
		native_openssl_error(ptr, "Error setting private key");
		return NATIVE_OPENSSL_ERROR_INVALID_PKEY;
	}
	
	if (!SSL_CTX_check_private_key (ptr->ctx)) {
		native_openssl_error(ptr, "Private key does not match public key");
		return NATIVE_OPENSSL_ERROR_PKEY_DOES_NOT_MATCH;
	}
	
	return 0;
}

int
native_openssl_BIO_get_mem_data (BIO *bio, void **data)
{
	return BIO_get_mem_data (bio, data);
}

static int
cert_verify_cb (X509_STORE_CTX *ctx, void *arg)
{
	NativeOpenSsl *ptr = (NativeOpenSsl*)arg;
	return ptr->cert_verify_callback (ctx, ctx->cert);
}

void
native_openssl_set_certificate_verify (NativeOpenSsl *ptr, int mode, VerifyCallback verify_cb,
				       CertificateVerifyCallback cert_cb, int depth)
{
	SSL_CTX_set_verify (ptr->ctx, mode, verify_cb);
	if (cert_cb) {
		ptr->cert_verify_callback = cert_cb;
		SSL_CTX_set_cert_verify_callback(ptr->ctx, cert_verify_cb, ptr);
	}
	SSL_CTX_set_verify_depth (ptr->ctx, depth);
}

void
native_openssl_add_trusted_ca (NativeOpenSsl *ptr, const char *CAfile, const char *CApath)
{
	SSL_CTX_load_verify_locations(ptr->ctx, CAfile, CApath);
}

void
native_openssl_free_certificate (X509 *certificate)
{
	X509_free (certificate);
}

void
native_openssl_free_private_key (EVP_PKEY *private_key)
{
	EVP_PKEY_free (private_key);
}

int
native_openssl_create_context (NativeOpenSsl *ptr, short client_p)
{
	const SSL_METHOD *method;
	
	method = client_p ? TLSv1_2_client_method () : TLSv1_2_server_method ();
	
	ptr->ctx = SSL_CTX_new (method);
	if (!ptr->ctx) {
		native_openssl_error(ptr, "Failed to create context.");
		return NATIVE_OPENSSL_ERROR_CREATE_CONTEXT;
	}

	if (!client_p) {
		DH *dh = get_dh512();
		if (dh)
			SSL_CTX_set_tmp_dh(ptr->ctx, dh);
	}

	return 0;

}

int
native_openssl_create_connection (NativeOpenSsl *ptr)
{
	ptr->ssl = SSL_new (ptr->ctx);
	if (!ptr->ssl) {
		native_openssl_error(ptr, "Failed to create connection.");
		return NATIVE_OPENSSL_ERROR_CREATE_CONNECTION;
	}
	
	return 0;
	
}

short
native_openssl_get_current_cipher (NativeOpenSsl *ptr)
{
	return (short)SSL_get_current_cipher (ptr->ssl)->id;
}

int
native_openssl_set_cipher_list (NativeOpenSsl *ptr, const void *codes, int count)
{
	STACK_OF(SSL_CIPHER*) ciphers;
	int i;

	ciphers = sk_SSL_CIPHER_new_null();

	for (i = 0; i < count; i++) {
		const SSL_CIPHER *c = ptr->ctx->method->get_cipher_by_char (codes + 2 * i);
		if (!c)
			return NATIVE_OPENSSL_ERROR_INVALID_CIPHER;
		sk_SSL_CIPHER_insert(ciphers, c, i);
	}

	ptr->ctx->cipher_list = ciphers;
	ptr->ctx->cipher_list_by_id = sk_SSL_CIPHER_dup(ciphers);

	return 0;
}

