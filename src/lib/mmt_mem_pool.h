/*
 * mmt_mem_pool.h
 *
 *  Created on: Jan 30, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_LIB_MMT_MEM_POOL_H_
#define SRC_LIB_MMT_MEM_POOL_H_
#include <stdlib.h>
#include <stdint.h>


////////One pool
typedef struct mmt_mem_pool_struct{
	uint32_t element_size;		   //size of one element
	uint32_t elements_count;     //number of elements being available
	uint32_t max_elements_count; //number of available elements being allowed
}mmt_mem_pool_t;

mmt_mem_pool_t * mmt_mem_pool_create( size_t element_size, size_t max_elements_count );

void mmt_mem_pool_free( mmt_mem_pool_t *, void (*free_fn)(void *) );

void mmt_mem_pool_reset( mmt_mem_pool_t * );

void * mmt_mem_pool_allocate_element( mmt_mem_pool_t *,  void *(*malloc_fn)(size_t) );

void mmt_mem_pool_free_element( mmt_mem_pool_t *, void *, void (*free_fn)(void *) );

#endif /* SRC_LIB_MMT_MEM_POOL_H_ */
