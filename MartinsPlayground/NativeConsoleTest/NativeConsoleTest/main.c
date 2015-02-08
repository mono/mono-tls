//
//  main.c
//  ConsoleTest
//
//  Created by Martin Baulig on 27/11/14.
//  Copyright (c) 2014 Xamarin. All rights reserved.
//

#include <stdio.h>
#include "../../NativeOpenSsl/NativeOpenSsl.h"

static void
load_certificate(NativeOpenSsl *ptr, const char *certfile, const char *keyfile)
{
	native_openssl_load_certificate_2(ptr, certfile);
	native_openssl_load_private_key_2(ptr, keyfile);
	native_openssl_create_context(ptr, 0);
}

int main
(int argc, const char * argv[])
{
	unsigned char ip[4] = { 0x7f, 0x00, 0x00, 0x01 };
	NativeOpenSsl *ptr;
	int ret;
	
	ptr = native_openssl_initialize ();
    
    if (argc == 2) {
        load_certificate(ptr, argv[0], argv[1]);
        native_openssl_bind(ptr, ip, 4433);
        native_openssl_accept(ptr);
    } else {
        native_openssl_connect(ptr, ip, 4433);
    }
	
	native_openssl_write(ptr, "TEST\n", 0, 5);

	return ret;
}
