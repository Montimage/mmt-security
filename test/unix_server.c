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
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
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



int main (int argc, char *argv[]) {
	int sockfd, newsockfd;
	struct sockaddr_un local, cli_addr;
	char str[100];
	socklen_t socklen;
	pthread_t pthread;
	user_data_t *user_data;

	mmt_assert( argc == 2, "Usage: %s unix_socket", argv[0] );

	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	 memset(&local, 0, sizeof(struct sockaddr_un));
	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, argv[1] );
	unlink(local.sun_path);

	if (bind(sockfd, (struct sockaddr *)&local, strlen(local.sun_path) + sizeof(local.sun_family)) == -1) {
		perror("bind");
		exit(1);
	}

	if (listen(sockfd, 5) == -1) {
		perror("listen");
		exit(1);
	}

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

	return 0;
}
