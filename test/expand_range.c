/*
 * expand_range.c
 *
 *  Created on: Jan 4, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */


#include "../src/lib/mmt_lib.h"

void expand( const char *string ){
	size_t i, size;
	uint8_t *array;
	size = expand_number_range( string, &array );
	printf("\n %s = ", string );

	if( size == 0 ){
		printf("error\n");
		return;
	}
	for( i=0; i<size; i++ )
		printf("%d%c", array[i], i<size-1?',':' ' );
	mmt_mem_free( array );
}

int main(){

	size_t size;

	//size = expand_number_range("1,3-5,8,12-13", &array );
	//consume( array, size );

	expand("12-13,1,3,4-5,1-10");
	expand("3,7,8-11");

	return 0;
}
