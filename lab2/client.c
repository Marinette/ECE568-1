#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"

#define HOST "localhost"
#define PORT 8765

#define OK 0
#define ADDRESS_ERROR -1
#define SOCKET_ERROR -2
#define CONNECT_ERROR -3

#define CLIENT_CERTIFICATE "alice.pem"
#define CA_CERTIFICATE "568ca.pem"

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

/* Utility*/
void parseArguments(int argc, char** argv, Connection* conn){
	switch (argc){
	case 1:
		break;
	case 3:
		conn->host = argv[1];
		conn->port = atoi(argv[2]);
		if (conn->port<1 || conn->port>65535){
			fprintf(stderr, "invalid port number");
			exit(0);
		}
		break;
	default:
		printf("Usage: %s server port\n", argv[0]);
		exit(0);
	}
}

// Check certification
int checkClientCertification(SSL* ssl, char* host){



}

void handleError(SSL * ssl, int ret){
	switch (SSL_get_error(ssl, ret)){
	case SSL_ERROR_NONE:
		return;
	case SSL_ERROR_SYSCALL:
		printf(FMT_INCORRECT_CLOSE);
		break;
	case SSL_ERROR_SSL:
		printf("Protocal Error\n");
	}

	// print inner error
	ERR_print_errors_fp(stderr);
}


/* Tcp Connection */
void tcpDisconnect(Connection* connection){
	if (connection->socket){
		close(connection->socket);
	}
}

int tcpConnect(Connection* connection){
	struct hostent *host_entry;

	/*get ip address of the host*/
	host_entry = gethostbyname(connection->host);
	if (!host_entry){
		fprintf(stderr, "Couldn't resolve host");
		return ADDRESS_ERROR;
	}

	/* set up socket stream*/
	memset(&connection->sin, 0, sizeof(connection->sin));
	connection->sin.sin_addr = *(struct in_addr *) host_entry->h_addr_list[0];
	connection->sin.sin_family = AF_INET;
	connection->sin.sin_port = htons(connection->port);

	printf("Connecting to %s(%s):%d\n", connection->host, inet_ntoa(connection->sin.sin_addr), connection->port);

	/*open socket*/
	if ((connection->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
		perror("socket");
		return SOCKET_ERROR;
	}
	if (connect(connection->socket, (struct sockaddr *)&connection->sin, sizeof(connection->sin)) < 0){
		perror("connect");
		return CONNECT_ERROR;
	}

	return OK;
}

/* Message Handling */
void processMessage(int sock){
	int len;
	char buf[256];
	char *secret = "What's the question?";

	send(sock, secret, strlen(secret), 0);
	len = recv(sock, &buf, 255, 0);
	buf[len] = '\0';

	/* this is how you output something for the marker to pick up */
	printf(FMT_OUTPUT, secret, buf);
}




/* Main Entry */
int main(int argc, char **argv)
{
	// init connection object
	Connection conn;
	memset(&conn, 0, sizeof(conn));
	conn.port = PORT; // assign default port
	conn.host = HOST;

	// Parse arguments
	parseArguments(argc, argv, &conn);

	// init SSL library
	conn.sslContext = initSSLContext(CLIENT_CERTIFICATE, CA_CERTIFICATE);
	SSL_CTX_set_options(conn.sslContext, SSL_OP_NO_SSLv2);
	SSL_CTX_set_cipher_list(conn.sslContext, "SHA1");

	// Connect
	if (tcpConnect(&conn) < 0){
		tcpDisconnect(&conn);
		exit(0);
	}

	SSL * ssl = SSL_new(ctx);
	BIO * sbio = BIO_new_socket(sock, BIO_NOCLOSE);
	SSL_set_bio(ssl, sbio, sbio);
	int ret;

	ret = SSL_connect(ssl);
	if (ret <= 0){
		printf(FMT_CONNECT_ERR);
		handleError(ssl, ret);
		
	}
	else{

	}

	// Process Message
	processMessage(conn.socket);

	// Disconnect
	tcpDisconnect(&conn);
	return 1;
}
