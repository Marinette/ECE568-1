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

#define PORT 8765
#define BACK_LOG 5

#define OK 0
#define SOCKET_ERROR -1
#define BIND_ERROR -2
#define LISTEN_ERROR -3
#define ACCEPT_ERROR -4

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

#define SERVER_CERTIFICATE "bob.pem"
#define CA_CERTIFICATE "568ca.pem"

typedef void (messageCallback)(SSL*);



/* Utility*/
void parseArguments(int argc, char** argv, Connection* conn){
	switch (argc){
	case 1:
		break;
	case 2:
		conn->port = atoi(argv[1]);
		if (conn->port < 1 || conn->port>65535){
			fprintf(stderr, "invalid port number");
			exit(0);
		}
		break;
	default:
		printf("Usage: %s port\n", argv[0]);
		exit(0);
	}
}

// Check certification
int checkClientCertification(SSL* ssl, char* host){
	X509 *peer;
	char peer_CN[256];

	if (SSL_get_verify_result(ssl) != X509_V_OK)
		printf("Certificate doesn't verify");

	/*Check the common name*/
	peer = SSL_get_peer_certificate(ssl);
	X509_NAME_get_text_by_NID
		(X509_get_subject_name(peer),
		NID_commonName, peer_CN, 256);
	if (strcasecmp(peer_CN, host))
		printf("Common name doesn't match host name");
}


void handleError(SSL * ssl, int ret){
	switch (SSL_get_error(ssl, ret)){
		case SSL_ERROR_NONE:
			return;
		case SSL_ERROR_SYSCALL:
			printf(FMT_INCOMPLETE_CLOSE);
			break;
		case SSL_ERROR_SSL:
			printf("Protocal Error\n");
	}

	// print inner error
	ERR_print_errors_fp(stderr);
}




/* Server Function*/
void stopServer(Connection* connection){
	close(connection->socket);
}


int startServer(Connection* connection, messageCallback* callback){
	// local variables
	int sock;
	int optionVal = 1;
	pid_t pid;

	// create socket
	if ((connection->socket = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		perror("socket");
		return SOCKET_ERROR;
	}

	// set up socket address
	memset(&connection->sin, 0, sizeof(connection->sin));
	connection->sin.sin_addr.s_addr = INADDR_ANY;
	connection->sin.sin_family = AF_INET;
	connection->sin.sin_port = htons(connection->port);

	// set socket options
	setsockopt(connection->socket, SOL_SOCKET, SO_REUSEADDR, &optionVal, sizeof(optionVal));

	// bind socket to address
	if (bind(connection->socket, (struct sockaddr *)&connection->sin, sizeof(connection->sin)) < 0){
		perror("bind");
		return BIND_ERROR;
	}

	// start listening
	if (listen(connection->socket, BACK_LOG) < 0){
		perror("listen");
		return LISTEN_ERROR;
	}

	// start processing
	while (1){
		if ((sock = accept(connection->socket, NULL, 0)) < 0){
			perror("accept");
			stopServer(connection);
			close(sock);
			return ACCEPT_ERROR;
		}

		/*fork a child to handle the connection*/
		pid = fork();
		if (pid == 0){
			// child process
			// secure connection
			SSL * ssl = SSL_new(ctx);
			BIO * bio = BIO_new_socket(sock, BIO_NOCLOSE);
			SSL_set_bio(ssl, bio, bio);
			int ret;

			ret = SSL_accept(ssl);
			if (ret <= 0){
				printf(FMT_ACCEPT_ERR); // accept error
				handleError(ssl, ret);
			} else {
				(*messageCallback)(ssl);
			}

			// close ssl connection
			if (!SSL_shutdown(ssl)){
				close(sock);
				SSL_shutdown(ssl);
			}
			SSL_free(ssl);

			// close connection
			stopServer(connection);
			close(sock);
			return 0;
		}
		else{
			// parent process
			close(sock);
		}
	}

	return OK;
}




/* Message Handling */
void processMessage(SSL* ssl){
	char buf[256];
	char *answer = "42";
	int ret;

	// read request
	ret = SSL_read(ssl, buf, sizeof(buf));
	if (ret <= 0){
		handleError(ssl, ret);
		return;
	}
	
	// write response
	ret = SSL_write(ssl, answer, strlen(answer));
	if (ret <= 0){
		handleError(ssl, ret);
		return;
	}
}


/* Main Entry */
int main(int argc, char **argv)
{
	// init connection object
	Connection conn;
	memset(&conn, 0, sizeof(conn));
	conn.port = PORT; // assign default port

	// parse arguments
	parseArguments(argc, argv, &conn);

	// init SSL library
	conn.sslContext = initSSLContext(SERVER_CERTIFICATE, CA_CERTIFICATE);

	// explictly use SSL v2,v3 and TLS v1
	SSL_CTX_set_cipher_list(conn.sslContext, "SSLv2:SSLv3:TLSv1");
	SSL_CTX_set_verify(conn.sslContext, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);


	// start server
	if (startServer(&conn, &processMessage) < 0){
		stopServer(&conn);
		exit(0);
	}

	stopServer(&conn);
	destroySSLContext(conn.sslContext);
	return 1;
}
