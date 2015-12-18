#include "common.h"





SSL_CTX* initSSLContext(char* keyFile, char* caFile){
	SSL_CTX* ctx;
	SSL_METHOD * method;

	// init SSL library
	SSL_load_error_strings();
	SSL_library_init();
	BIO_new_fp(stderr, BIO_NOCLOSE);

	// create new context
	method = SSLv23_method();
	ctx = SSL_CTX_new(method);

	// load certificate and password
	SSL_CTX_use_certificate_chain_file(ctx, keyFile);
	SSL_CTX_set_default_passwd_cb(ctx, passwordCallback);
	SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM);
	SSL_CTX_load_verify_locations(ctx, caFile, 0);

#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
	SSL_CTX_set_verify_depth(ctx, 1);
#endif

	return ctx;
}



// password callback
int passwordCallback(char *buf, int size, int rwflag, void *password)
{
	strncpy(buf, (char *)(password), size);
	buf[size - 1] = '\0';
	return(strlen(buf));
}


void destroySSLContext(SSL_CTX * ctx) {
	SSL_CTX_free(ctx);
}
