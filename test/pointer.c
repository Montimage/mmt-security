/*
 * pointer.c
 *
 *  Created on: 23 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "../src/lib/base.h"
#include "../src/lib/expression.h"
#include "../src/lib/mmt_log.h"
#include "../src/lib/mmt_alloc.h"

void set_string( char **p ){
	*p = mmt_malloc(3);
	memcpy( *p, "xxx", 3);
}

void set_null( int *p){
	p = NULL;
}

int main(){
	char *ptr = NULL;
	int *p = mmt_malloc( sizeof( int ));
	*p = 5;
	set_null( p );
	mmt_assert( p != NULL, "Not null %d", *p);

	set_string( &ptr );
	mmt_debug( "%s", ptr );

	mmt_free( ptr );
	ptr = NULL;

	set_string( &ptr );
	mmt_debug( "%s", ptr );
	mmt_free( ptr );
	ptr = NULL;

	return 0;
}
