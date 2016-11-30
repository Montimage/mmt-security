/*
 * tcp_server.c
 *
 *  Created on: Nov 24, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */


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
#include <pthread.h>
#include "../src/lib/system_info.h"
#include "../src/lib/mmt_lib.h"

typedef struct user_data_struct{
	int sock;
}user_data_t;

/*size of a report sent by mmt-probe*/
#define REPORT_SIZE 2000
void* processing (void *arg ) {

	int sock = ((user_data_t *)arg)->sock ;
   size_t ret, reports_count = 0 ;
   uint32_t len;
   uint8_t buffer[ REPORT_SIZE ]; //utf-8

   do{
   	ret = recv( sock, &len, 4, MSG_WAITALL);
   	if( ret == 0 ) break;

   	if( len > REPORT_SIZE ){
   		mmt_warn("Overflow: len = %d", len );
   		len = REPORT_SIZE;
   	}else if( len < 30 )
   		continue;
   	else if( len < 0 )
   		mmt_info("Impossible len = %d", len );

   	ret = recv( sock, buffer, len-4, MSG_WAITALL );
   	if( ret == 0 ) break;

   	if( ret > 10 )
   		reports_count ++;
   	else
   		mmt_error("Malformated!");

   }while( 1 );

   mmt_info("proc %d received %zu reports", gettid(), reports_count );
   close( sock );
   mmt_mem_free( arg );
   return NULL;
}

int main(int argc, char *argv[]) {
	int sockfd, newsockfd, portno;
	char buffer[256];
	struct sockaddr_in serv_addr, cli_addr;
	int n, pid;
	socklen_t socklen;
	pthread_t pthread;
	user_data_t *user_data;

	portno = 5001;

	mmt_assert( argc == 2, "Usage: %s port_number", argv[0] );
	portno = atoi( argv[ 1 ] );

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

	mmt_info("Listening on port %d", portno );

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

		mmt_info("A new connection is coming ...");

		user_data = mmt_mem_alloc( sizeof( user_data_t ));
		user_data->sock = newsockfd;

		/* Create thread to receive data */
		if( pthread_create( &pthread, NULL, processing, user_data ) ){
			mmt_warn("Cannot create new thread");
			mmt_mem_free( user_data );
		}
	} /* end of while */
}
