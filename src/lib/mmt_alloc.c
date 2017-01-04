/*
 * mmt_alloc.c
 *
 *  Created on: 19 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */
#include <stdint.h>
#include "base.h"
#include "mmt_alloc.h"
#include "mmt_log.h"

const static size_t size_of_mmt_memory_t = sizeof( mmt_memory_t );

/**
 * Public API
 */
void mmt_mem_info( size_t *allocated, size_t *freed ){
	mmt_assert( allocated != NULL && freed != NULL, "Variables are NULL");
	*allocated = 0;//allocated_memory_size;
	*freed     = 0;//freed_memory_size;
}

void mmt_mem_print_info(){
	//mmt_log(INFO, "MMT allocated: %zu bytes, freed: %zu bytes", allocated_memory_size, freed_memory_size );
}

void *mmt_mem_alloc(size_t size){
	if( unlikely( size == 0 )) return NULL;

	size = size_of_mmt_memory_t + size + 1;
	mmt_memory_t *mem = malloc( size );

	//quit if not enough
	mmt_assert( mem != NULL, "Not enough memory to allocate %zu bytes", size);
	//remember size of memory being allocated
	//allocated_memory_size += size;

	//safe string
	((char *)mem)[ size-1 ] = '\0';

	//mem->data points to the memory segment after sizeof( mmt_memory_t )
	mem->data = mem + 1;
	//store size to head of the memory segment
	mem->size      = size;
	mem->ref_count = 1;

	return mem->data;
}


size_t mmt_mem_free( void *x ){
	__check_null( x, 0);

   mmt_memory_t *mem = mmt_mem_revert( x );
   if( mem->ref_count <= 1 ){
		//freed_memory_size += mem->size;
		free( mem );
		return 0;
   }else{
   	mem->ref_count --;
   	return mem->ref_count;
   }
}

size_t mmt_mem_force_free( void *x ){
	__check_null( x, 0);

   mmt_memory_t *mem = mmt_mem_revert( x );
   free( mem );
	return 0;
}

void *mmt_mem_retain( void *x ){
	__check_null( x, NULL );  // nothing to do
   mmt_memory_t *mem = mmt_mem_revert( x );
   mem->ref_count ++;
   return mem->data;
}


void *mmt_mem_retains( void *x, size_t retains_count ){
	__check_null( x, NULL );  // nothing to do
   mmt_memory_t *mem = mmt_mem_revert( x );
   mem->ref_count += retains_count;
   return mem->data;
}

size_t mmt_mem_size( const void *x ){
	__check_null( x, 0 );  // nothing to do

   mmt_memory_t *mem = mmt_mem_revert( x );
   return mem->size;
}

size_t mmt_mem_reference_count( void *x ){
	if( x == NULL ) return 0; // nothing to do
	mmt_memory_t *mem = mmt_mem_revert( x );
	return mem->ref_count;
}
