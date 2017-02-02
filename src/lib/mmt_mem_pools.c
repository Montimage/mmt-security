/*
 * mmt_mem_pools.c
 *
 *  Created on: Feb 2, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "mmt_mem_pools.h"

mmt_mem_pools_map_t * mmt_mem_pools_map_create( size_t max_elements_count ){
	mmt_mem_pools_map_t *pools    = malloc( sizeof( mmt_mem_pools_map_t ));
	pools->pools_count        = 0;
	pools->elements_count     = 0;
	pools->max_elements_count = 0;
	pools->pools_map          = mmt_map_init( compare_uint32_t );
	return pools;
}

static void _free_pool( mmt_mem_pool_t *pool ){
	mmt_mem_pool_free( pool, (void *)mmt_mem_free );
}

void mmt_mem_pools_map_delete( mmt_mem_pools_map_t * pools ){
	mmt_map_free_key_and_data( pools->pools_map, (void *)mmt_mem_free, (void *)_free_pool );
	mmt_mem_free( pools );
}
