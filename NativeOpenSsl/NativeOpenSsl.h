//
//  NativeOpenSsl.h
//  NativeOpenSsl
//
//  Created by Martin Baulig on 27/11/14.
//  Copyright (c) 2014 Xamarin. All rights reserved.
//

#ifndef __NativeOpenSsl__
#define __NativeOpenSsl__

#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>

typedef void (* DebugCallback) (int cmd, const char *ptr, int size, int ret);

typedef void (* MessageCallback) (int write_p, int version, int content_type, const void *buf, int size);

typedef int (* VerifyCallback) (int ok, X509_STORE_CTX *ctx);

typedef int (* CertificateVerifyCallback) (X509_STORE_CTX *ctx, X509 *cert);

typedef enum {
	OK,
	NATIVE_OPENSSL_ERROR_SOCKET,
	NATIVE_OPENSSL_ERROR_SSL_CONNECT,
	NATIVE_OPENSSL_ERROR_SSL_ACCEPT,
	NATIVE_OPENSSL_ERROR_PKCS12_LOAD,
	NATIVE_OPENSSL_ERROR_PKCS12_VERIFY,
	NATIVE_OPENSSL_ERROR_PKCS12_PARSE,
	NATIVE_OPENSSL_ERROR_INVALID_CERT,
	NATIVE_OPENSSL_ERROR_INVALID_PKEY,
	NATIVE_OPENSSL_ERROR_PKEY_DOES_NOT_MATCH,
	NATIVE_OPENSSL_ERROR_CREATE_CONTEXT,
	NATIVE_OPENSSL_ERROR_CREATE_CONNECTION,
	NATIVE_OPENSSL_ERROR_INVALID_CIPHER
} NativeOpenSslError;

typedef enum {
	NATIVE_OPENSSL_PROTOCOL_TLS10,
	NATIVE_OPENSSL_PROTOCOL_TLS11,
	NATIVE_OPENSSL_PROTOCOL_TLS12
} NativeOpenSslProtocol;

typedef struct {
	int debug;
	NativeOpenSslProtocol protocol;
	int is_server;
	int socket;
	int accepted;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *sbio;
	DebugCallback debug_callback;
	MessageCallback message_callback;
	VerifyCallback verify_callback;
	CertificateVerifyCallback cert_verify_callback;
	DH *dh_params;
} NativeOpenSsl;

NativeOpenSsl *
native_openssl_initialize (int debug, NativeOpenSslProtocol protocol, DebugCallback debug_callback, MessageCallback message_callback);

int
native_openssl_set_dh_params (NativeOpenSsl *ptr, const unsigned char *p, int p_len, const unsigned char *g, int g_len);

int
native_openssl_connect (NativeOpenSsl *ptr, unsigned char ip[4], int port);

int
native_openssl_bind (NativeOpenSsl *ptr, unsigned char ip[4], int port);

int
native_openssl_accept (NativeOpenSsl *ptr);

int
native_openssl_write (NativeOpenSsl *ptr, const void *buf, int offset, int size);

int
native_openssl_read (NativeOpenSsl *ptr, void *buf, int offset, int size);

int
native_openssl_load_certificate_from_pkcs12 (NativeOpenSsl *ptr, const void *buf, int len,
					     const char *password, int passlen,
					     X509 **out_certificate, EVP_PKEY **out_private_key);

X509 *
native_openssl_load_certificate_from_pem (NativeOpenSsl *ptr, const void *buf, int len);

EVP_PKEY *
native_openssl_load_private_key_from_pem (NativeOpenSsl *ptr, const void *buf, int len);

X509 *
native_openssl_load_certificate_from_file (NativeOpenSsl *ptr, const char *filename);

EVP_PKEY *
native_openssl_load_private_key_from_file (NativeOpenSsl *ptr, const char *filename);

int
native_openssl_set_certificate (NativeOpenSsl *ptr, X509 *certificate, EVP_PKEY *private_key);

void
native_openssl_set_certificate_verify (NativeOpenSsl *ptr, int mode, VerifyCallback verify_cb,
				       CertificateVerifyCallback cert_cb, int depth);

void
native_openssl_add_trusted_ca (NativeOpenSsl *ptr, const char *CAfile, const char *CApath);

int
native_openssl_BIO_get_mem_data (BIO *bio, void **data);

int
native_openssl_create_context (NativeOpenSsl *ptr, short client_p);

int
native_openssl_create_connection (NativeOpenSsl *ptr);

int
native_openssl_shutdown (NativeOpenSsl *ptr);

void
native_openssl_destroy (NativeOpenSsl *ptr);

void
native_openssl_close (NativeOpenSsl *ptr);

void
native_openssl_free_certificate (X509 *certificate);

void
native_openssl_free_private_key (EVP_PKEY *private_key);

short
native_openssl_get_current_cipher (NativeOpenSsl *ptr);

int
native_openssl_set_cipher_list (NativeOpenSsl *ptr, const void *codes, int count);

#endif /* defined(__NativeOpenSsl__) */
