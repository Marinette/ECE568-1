#include "common.h"



SSL_CTX* initSSLContext(char* keyFile, char* password){
	SSL_CTX* ctx;

	// init SSL library
	SSL_load_error_strings();
	SSL_library_init();
	BIO_new_fp(stderr, BIO_NOCLOSE);

	// create new context
	ctx = SSL_CTX_new(SSLv23_method());

	signal(SIGPIPE, sigpipe_handle);

	if (!SSL_CTX_use_certificate_chain_file(ctx, keyFile)){
		berr_exit("Can't read key file");
	}

	SSL_CTX_set_default_passwd_cb(ctx, password_cb);
	if (!SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILE))
}





