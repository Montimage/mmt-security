/*
 * unix_client.c
 *
 *  Created on: Jan 9, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

/* a client in the unix domain */
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
void error(const char *);

int main(int argc, char *argv[]) {
	int sockfd, servlen, n;
	struct sockaddr_un serv_addr;
	char buffer[82];

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sun_family = AF_UNIX;
	strcpy(serv_addr.sun_path, argv[1]);
	servlen = strlen(serv_addr.sun_path) + sizeof(serv_addr.sun_family);
	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) error("Creating socket");
	if (connect(sockfd, (struct sockaddr *) &serv_addr, servlen) < 0) error(
			"Connecting");
	printf("Please enter your message: ");
	bzero(buffer, 82);
	fgets(buffer, 80, stdin);
	write(sockfd, buffer, strlen(buffer));
	n = read(sockfd, buffer, 80);
	printf("The return message was\n");
	write(1, buffer, n);
	close(sockfd);
	return 0;
}

void error(const char *msg) {
	perror(msg);
	exit(0);
}
