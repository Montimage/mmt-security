/*
 * set64.c
 *
 *  Created on: Sep 6, 2018
 *          by: Huu Nghia Nguyen
 */


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include "../src/lib/mmt_set64.h"

#define LOOP 10000000

int main() {
	mmt_set64_t *set = mmt_set64_create();

	int i;

	srand( time(NULL) );

	for( i = 0 ; i < LOOP ; i++ ) {
		int val = rand();

		mmt_set64_add(set, val);

		assert( mmt_set64_check(set, val) );

	}

	return 0;
}
