/*
 * output.c
 *
 *  Created on: Dec 15, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */


#include "../src/lib/mmt_lib.h"

void init_file( const char *);

int main(){
	init_file( "file:///home/tata/");
	init_file( "file:///home/tata/:5");
	init_file( "file:///home/tata/:5 ");
	init_file( "file:///home/tata/:58:d");
	return 0;
}
