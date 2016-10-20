/*
 * parse.c
 *
 *  Created on: 26 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include <string.h>
#include "../src/lib/base.h"
#include "../src/lib/expression.h"
#include "../src/lib/mmt_log.h"
#include "../src/lib/mmt_alloc.h"
#include "../src/lib/data_struct.h"

int main(){
	char *ptr = NULL, *data = mmt_mem_dup("xxx", 3), *key=mmt_mem_dup( "a", 1);
	void *fun = &strcmp;
	int x=1,y=2,z=3;
	mmt_map_t *map = mmt_map_init( fun );
	mmt_map_set_data(map, key, data, NO );
	data = mmt_map_get_data( map, "a");
	mmt_assert( data != NULL && *data == 'x', "Not good for getting data %s", data );

	mmt_map_set_data(map, mmt_mem_dup( "key", 3 ), mmt_mem_dup( "yyyyy", 5 ), YES );


	data = mmt_mem_dup( "zzzzz", 5 );
	key  = mmt_mem_dup( "key", 3 );
	//mem leak if do not free data and key
	ptr = mmt_map_set_data(map, key, data, YES );

	mmt_assert( ptr != NULL && *ptr == 'y', "Not good for duplicated key %s", key );
	mmt_mem_free( ptr ); //free the old data, not data
	mmt_mem_free( key );

	ptr = mmt_map_get_data( map, "key" );
	mmt_assert( ptr != NULL && *ptr == 'z', "Not good for get data %s", key );

	mmt_assert( mmt_map_count( map ) == 2, "Not good for counting map");

	mmt_map_free( map, YES );

	map = mmt_map_init( compare_uint8_t );
	mmt_map_set_data( map, &x, &y, YES );

	mmt_debug("Data : %d", *(int *)(mmt_map_get_data(map, &x)));
	mmt_map_free( map, NO );

	return 0;
}
