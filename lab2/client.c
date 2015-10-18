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
#define SSL_ERROR -4

#define CLIENT_CERTIFICATE "alice.pem"
#define CA_CERTIFICATE "568ca.pem"
#define SERVER_CN "Bob's Server"
#define SERVER_EMAIL "ece568bob@ecf.utoronto.ca"

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
int checkServerCertification(SSL* ssl){

	X509* peer = SSL_get_peer_certificate(ssl);

	if (!peer || (SSL_get_verify_result(ssl) != X509_V_OK) ) {
		fprintf(stderr, FMT_NO_VERIFY); // Certificate does not verify
		return SSL_ERROR;
	}

	//print client certificate info
	char commonName[256];
	char email[256];
	char issuer[256];

	X509_NAME *peerSubjectName = X509_get_subject_name(peer);
	X509_NAME_get_text_by_NID(peerSubjectName, NID_commonName, commonName, 256);
	X509_NAME_get_text_by_NID(peerSubjectName, NID_pkcs9_emailAddress, email, 256);

	X509_NAME *issuer_name = X509_get_issuer_name(peer);
	X509_NAME_get_text_by_NID(issuer_name, NID_commonName, issuer, 256);

	X509_free(peer);

	// Check CN
	if (strcasecmp(commonName, SERVER_CN) != OK) {
		fprintf(stderr, FMT_CN_MISMATCH); // Common Name mismatch
		return SSL_ERROR;
	}
	// Check email
	if (strcasecmp(email, SERVER_EMAIL) != OK) {
		fprintf(stderr, FMT_EMAIL_MISMATCH); // Email mismatch
		return SSL_ERROR;
	}

	// print out client info
	printf(FMT_SERVER_INFO, commonName, email, issuer);

	return OK;
}

void handleError(SSL * ssl, int ret){
	switch (SSL_get_error(ssl, ret)){
	case SSL_ERROR_NONE:
		return;
	case SSL_ERROR_SYSCALL:
		printf(FMT_INCORRECT_CLOSE); // incomplete close
		break;
	case SSL_ERROR_SSL:
		break;
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
void processMessage(SSL* ssl){
	int ret;
	char buf[256];
	char *secret = "What's the question?";
	memset(buf, 0, sizeof(buf));

	// write question
	ret = SSL_write(ssl, secret, strlen(secret));
	if (ret <= 0){
		handleError(ssl, ret);
		return;
	}

	// read answer
	ret = SSL_read(ssl, buf, sizeof(buf));
	if (ret <= 0){
		handleError(ssl, ret);
		return;
	}

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

	SSL * ssl = SSL_new(conn.sslContext);
	BIO * sbio = BIO_new_socket(conn.socket, BIO_NOCLOSE);
	SSL_set_bio(ssl, sbio, sbio);
	int ret;

	ret = SSL_connect(ssl);
	if (ret <= 0){
		printf(FMT_CONNECT_ERR);
		handleError(ssl, ret);
	}
	else{
		// Process Message
		if (checkServerCertification(ssl) == OK){
			processMessage(ssl);
		}
	}

	// close ssl connection
	if (!SSL_shutdown(ssl)){
		tcpDisconnect(&conn);
		SSL_shutdown(ssl);
	}
	SSL_free(ssl);

	// Disconnect
	tcpDisconnect(&conn);
	destroySSLContext(conn.sslContext);
	return 1;
}
