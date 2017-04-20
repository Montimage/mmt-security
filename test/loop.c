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

static volatile uint64_t val = 3;

void signal_handler(int signal_type) {
	printf( "\nvalue = %"PRIu64"\n", val );
	exit( signal_type );
}


int main( int argc, char **argv){
	signal(SIGINT,  signal_handler);
	while( 1 ){
		val ++;
	}
	return EXIT_SUCCESS;
}
