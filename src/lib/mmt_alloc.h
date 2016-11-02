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
void *mmt_mem_alloc( size_t size );
/**
 * Free memory allocated by mmt_malloc
 * Do not use this function to free memory created by malloc
 */
void  mmt_mem_free( void *ptr );

/**
 * Get information about memory being allocated and freed
 * - Input:
 * - Output:
 * 	+ allocated: number of bytes being allocated
 * 	+ freed    : number of bytes being freed
 * - Return:
 * - Error:
 * 	+ Exist the system if the parameters are NULL
 */
void mmt_mem_info( size_t *allocated, size_t *freed );

/**
 * Print information about memory allocated and freed
 */
void mmt_mem_print_info();
/**
 * Get size of the memory segment pointed by ptr.
 * Note that ptr is the pointer created by one of function: mmt_malloc, mmt_calloc
 * - Error:
 * 	+ Maybe crashed if ptr is not created by mmt_malloc or mmt_calloc
 */
size_t mmt_mem_size( const void *ptr );

/**
 * Duplicate a memory
 * - Input:
 * 	+ ptr: data to be duplicated
 * 	+ size: size of data
 * - Output:
 * - Return
 * 	+ new data being duplicated
 */
static inline void* mmt_mem_dup( const void *ptr, size_t size ){
	if( ptr == NULL || size == 0 ) return NULL;
	void *ret = mmt_mem_alloc( size );
	memcpy( ret, ptr, size );
	return ret;
}

/**
 * Increase number of reference to the memory to 1
 * - Input:
 * 	+ ptr: data to be increase
 * - Return:
 * 	a pointer point to #ptr;
 */
void *mmt_mem_retain( void *ptr );

/**
 * Return number of pointers pointing to this memory
 */
size_t mmt_mem_reference_count( void *ptr );

#define mmt_free_and_assign_to_null( x ) while( x != NULL ){ mmt_mem_free( x ); x = NULL; break; }

#endif /* SRC_MMT_ALLOC_H_ */
