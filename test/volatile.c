/*
 * loop.c
 *
 *  Created on: Apr 20, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@me.com>
 */



#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>

static volatile int is_exit = 0;

void signal_handler(int signal_type) {
	is_exit = 1;
}


int main( int argc, char **argv){
	uint64_t val = 10;
	signal(SIGINT,  signal_handler);
	while( !is_exit ){
		val ++;
	}

	printf( "\nvalue = %"PRIu64"\n", val );
	return EXIT_SUCCESS;
}
