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

/* Callback definition */
typedef void (callback)(int);



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




/* Server Function*/
void stopServer(Connection* connection){
	close(connection->socket);
}


int startServer(Connection* connection, callback* cb){
	// local variables
	int acceptSock;
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
		if ((acceptSock = accept(connection->socket, NULL, 0)) < 0){
			perror("accept");
			close(acceptSock);
			return ACCEPT_ERROR;
		}

		/*fork a child to handle the connection*/
		pid = fork();
		if (pid == 0){
			// child process execute callback
			(*cb)(acceptSock);
			// close connection
			stopServer(connection);
			close(acceptSock);
			return 0;
		}
		else{
			// parent process
			close(acceptSock);
		}
	}

	return OK;
}



/* Message Handling */
void processMessage(int sock){
	int len;
	char buf[256];
	char *answer = "42";

	len = recv(sock, &buf, 255, 0);
	buf[len] = '\0';
	printf(FMT_OUTPUT, buf, answer);
	send(sock, answer, strlen(answer), 0);
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

	// start server
	if (startServer(&conn, &processMessage) < 0){
		stopServer(&conn);
		exit(0);
	}

	stopServer(&conn);
	return 1;
}
