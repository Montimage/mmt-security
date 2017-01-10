/*
 * mmt_alloc.h
 *
 *  Created on: 19 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 *  A wrapper for malloc, free, calloc, realloc
 *  By using this wrapper, we can know how much memory are allocated/free
 */

#ifndef SRC_MMT_ALLOC_H_
#define SRC_MMT_ALLOC_H_

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "base.h"
#include "mmt_alloc.h"
#include "mmt_log.h"


typedef struct mmt_memory_struct{
	size_t ref_count;
	size_t  size;
	void *  data;
}mmt_memory_t;

#define mmt_mem_revert( x ) (mmt_memory_t *) ( (uint8_t*)x - sizeof( mmt_memory_t ) )

const static size_t size_of_mmt_memory_t = sizeof( mmt_memory_t );

/**
 * A wrapper of malloc
 * Allocate a new segment of memory having the given size.
 * The segment is appended an extra byte containing by '\0'
 * - Input:
 * 	+ size: size to be allocated
 * - Output:
 * - Return:
 * 	+ new segment allocated
 * - Error:
 * 	+ Exit system if memory is not enough
 */
static inline
void *mmt_mem_alloc(size_t size){

#ifdef DEBUG_MODE
	mmt_assert( size > 0, "Size must not be negative" );
#endif

	size = size_of_mmt_memory_t + size + 1;
	mmt_memory_t *mem = malloc( size );

	//quit if not enough
	mmt_assert( mem != NULL, "Not enough memory to allocate %zu bytes", size);
	//remember size of memory being allocated
	//allocated_memory_size += size;

	//safe string
	((char *)mem)[ size-1 ] = '\0';

	//mem->data points to the memory segment after sizeof( mmt_memory_t )
	mem->data      = mem + 1;
	//store size to head of the memory segment
	mem->size      = size;
	mem->ref_count = 1;

	return mem->data;
}

/**
 * Free memory allocated by mmt_malloc
 * Do not use this function to free memory created by malloc
 */
static inline
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


/**
 * Free memory allocated by mmt_malloc
 * Do not use this function to free memory created by malloc
 * @param x
 */
static inline
void mmt_mem_force_free( void *x ){
#ifdef DEBUG_MODE
	mmt_assert( x != NULL, "x (%p) must not be NULL", x );
#endif

	mmt_memory_t *mem = mmt_mem_revert( x );
   free( mem );
}

/**
 * Get size of the memory segment pointed by ptr.
 * Note that ptr is the pointer created by one of function: mmt_malloc, mmt_calloc
 * - Error:
 * 	+ Maybe crashed if ptr is not created by mmt_malloc or mmt_calloc
 */
static inline
size_t mmt_mem_size( const void *x ){
	__check_null( x, 0 );  // nothing to do

   mmt_memory_t *mem = mmt_mem_revert( x );
   return mem->size;
}

/**
 * Duplicate a memory
 * - Input:
 * 	+ ptr: data to be duplicated
 * 	+ size: size of data
 * - Output:
 * - Return
 * 	+ new data being duplicated
 */
static inline
void* mmt_mem_dup( const void *ptr, size_t size ){
	__check_null( ptr, NULL );  // nothing to do

	void *ret = mmt_mem_alloc( size );
	memcpy( ret, ptr, size );
//	rte_memcpy( ret, ptr, size );
	return ret;
}

/**
 * Increase number of reference to the memory to 1
 * - Input:
 * 	+ ptr: data to be increase
 * - Return:
 * 	a pointer point to #ptr;
 */
static inline
void *mmt_mem_retain( void *x ){
	__check_null( x, NULL );  // nothing to do
   mmt_memory_t *mem = mmt_mem_revert( x );
   mem->ref_count ++;
   return mem->data;
}

static inline
void *mmt_mem_retains( void *x, size_t retains_count ){
	__check_null( x, NULL );  // nothing to do
   mmt_memory_t *mem = mmt_mem_revert( x );
   mem->ref_count += retains_count;
   return mem->data;
}

/**
 * Return number of pointers pointing to this memory
 */
static inline
size_t mmt_mem_reference_count( void *x ){
	if( x == NULL ) return 0; // nothing to do
	mmt_memory_t *mem = mmt_mem_revert( x );
	return mem->ref_count;
}

#define mmt_free_and_assign_to_null( x ) while( x != NULL ){ mmt_mem_free( x ); x = NULL; break; }

#endif /* SRC_MMT_ALLOC_H_ */
