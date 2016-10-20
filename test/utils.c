/*
 * utils.c
 *
 *  Created on: 22 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */


#include "../src/lib/base.h"
#include "../src/lib/mmt_utils.h"
#include "../src/lib/mmt_log.h"
#include "../src/lib/mmt_alloc.h"

int main(){
	uint8_t *str = mmt_mem_alloc(5);
	str[0] = '0';str[1] = '1';str[2] = '2';str[3] = '3';str[4] = '4';
	mmt_assert( (find_byte( '2', str, 5 ) == 3), "Not found 2 %s", str );
	mmt_assert( (find_byte( '3', str, 5 ) == 4), "Not found 3 %s", str );
	printf("OK\n");
	return 0;
}
