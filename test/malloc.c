/*
 * log.c
 *
 *  Created on: 19 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "../src/lib/mmt_alloc.h"
#include "minunit.h"

int main() {
	void *x;
	x = mmt_mem_alloc( 5 );
	mmt_mem_free( x );

	x = mmt_mem_alloc( 5 );
	mmt_mem_free( x );

	x = mmt_mem_alloc( 15 );
	mmt_mem_free( x );

	x = mmt_mem_alloc( 15 );
		mmt_mem_free( x );
	return 0;
}
