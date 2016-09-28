/*
 * main.c
 *
 *  Created on: 20 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include "lib/mmt_log.h"

/*size of a report sent by mmt-probe*/
#define REPORT_SIZE 1000
void processing (int sock) {
   static size_t len;
   static uint8_t buffer[ REPORT_SIZE ]; //utf-8

   len = read( sock, (void *)buffer, REPORT_SIZE);
   if (len < 0)
      mmt_log(ERROR, "ERROR reading from socket");

   printf("Here is the message: %s\n",buffer);

   //ack?
   len = write(sock, &len, sizeof( size_t ));
}

int main(int argc, char *argv[]) {
	int sockfd, newsockfd, portno;
	char buffer[256];
	struct sockaddr_in serv_addr, cli_addr;
	int n, pid;
	socklen_t socklen;

	portno = 5001;

	/* First call to socket() function */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	mmt_assert( sockfd >= 0, "ERROR opening socket, errcode: %d", errno);

	/* Initialize socket structure */
	bzero((char *) &serv_addr, sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);

	/* Now bind the host address using bind() call.*/
	mmt_assert(bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) >= 0, "ERROR on binding");

	/* Now start listening for the clients, here
	 * process will go in sleep mode and will wait
	 * for the incoming connection
	 */
	listen(sockfd, 5);
	socklen = sizeof(cli_addr);

	while (1) {
		/* Accept actual connection from the client */
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &socklen);
		mmt_assert( newsockfd >= 0, "ERROR on accept");

		/* Create child process */
		pid = fork();
		mmt_assert (pid >= 0, "ERROR on fork");

		if (pid == 0) {
			/* This is the child process */
			close(sockfd);
			processing(newsockfd);
			exit(0);
		}
		else {
			close(newsockfd);
		}

	} /* end of while */
}
