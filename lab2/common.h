#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct{
	int socket;
	char* host;
	int port;
	struct sockaddr_in sin;
	SSL * sslHandle;
	SSL_CTX* sslContext;
} Connection;



SSL_CTX* initSSLContext();

