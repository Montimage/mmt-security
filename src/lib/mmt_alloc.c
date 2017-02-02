/*
 * mmt_alloc.c
 *
 *  Created on: 19 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */
#include <stdint.h>
#include "mmt_alloc.h"
#include "mmt_mem_pools.h"

static __thread mmt_mem_pools_map_t *mem_pools = NULL;

void *mmt_mem_alloc(size_t size){
#ifdef DEBUG_MODE
	mmt_assert( size > 0, "Size must not be negative" );
#endif

	mmt_memory_t *mem = malloc( SIZE_OF_MMT_MEMORY_T + size + 1 );

	//quit if not enough
	mmt_assert( mem != NULL, "Not enough memory to allocate %zu bytes", size);
	//remember size of memory being allocated
	//allocated_memory_size += size;

	//safe string
	((char *)mem)[ SIZE_OF_MMT_MEMORY_T + size ] = '\0';

	//mem->data points to the memory segment after sizeof( mmt_memory_t )
	mem->data      = mem + 1;
	//store size to head of the memory segment
	mem->size      = size;
	mem->ref_count = 1;

	return mem->data;
}


void mmt_mem_force_free( void *x ){
#ifdef DEBUG_MODE
	mmt_assert( x != NULL, "x (%p) must not be NULL", x );
#endif

   free( mmt_mem_revert( x ) );
}
