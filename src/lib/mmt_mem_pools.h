/*
 * mmt_mem_pools.h
 *
 *  Created on: Feb 2, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_LIB_MMT_MEM_POOLS_H_
#define SRC_LIB_MMT_MEM_POOLS_H_

#include "mmt_map_t.h"
#include "mmt_alloc.h"
#include "mmt_mem_pool.h"

//////More than one pool
typedef struct mmt_mem_pools_map_struct{
	uint32_t pools_count;    //number of pools
	uint32_t elements_count; //total number of elements of all pools
	size_t   max_elements_count;
	mmt_map_t *pools_map;
}mmt_mem_pools_map_t ;

mmt_mem_pools_map_t * mmt_mem_pools_map_create( size_t max_elements_count );

void mmt_mem_pools_map_delete( mmt_mem_pools_map_t * pools );


static inline void *mmt_mem_pools_map_alloc( mmt_mem_pools_map_t *pools, uint32_t elem_size ){
	mmt_mem_pool_t *pool = mmt_map_get_data( pools->pools_map, &elem_size );
	if( pool == NULL || pool->elements_count == 0 ){
		return mmt_mem_alloc( elem_size );
	}

	//reduce number of available elements
	pools->elements_count --;
	return mmt_mem_pool_allocate_element( pool, mmt_mem_alloc );
}

static inline void mmt_mem_pools_map_free( mmt_mem_pools_map_t * pools, void *elem ){
	mmt_memory_t *mem = mmt_mem_revert( elem );

	mem->ref_count --;

	if( mem->ref_count > 0 )//the element is still alive ==> do not touch to it
		return;

	//total pools is full => free memory
	if( pools->elements_count >= pools->max_elements_count ){
		free( mem );
		return;
	}

	//find a slot in set of pools to store this element
	mmt_mem_pool_t *pool = mmt_map_get_data( pools->pools_map, &(mem->size) );

	//its pool is full
	if( pool != NULL && pool->elements_count >= pool->max_elements_count ){
		free( mem );
		return;
	}

	//happen only one time when the pool for elem_size does not exist
	if( unlikely( pool == NULL )){
		pool = mmt_mem_pool_create( mem->size, 100 );
		//insert the pool into map
		mmt_map_set_data( pools->pools_map, mmt_mem_dup( &(mem->size), 4 ), pool, NO );
	}

	//store the element to the pool
	mmt_mem_pool_free_element( pool, elem, (void *)mmt_mem_free );
}

#endif /* SRC_LIB_MMT_MEM_POOLS_H_ */
