/*
 * mmt_alloc.c
 *
 *  Created on: 19 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */
#include <stdint.h>
#include "mmt_alloc.h"
#include "mmt_mem_pool.h"

///////////////////////////////////////////////////////////////////////////////
////memory
///////////////////////////////////////////////////////////////////////////////
static inline void *_mem_alloc(size_t size){
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

static inline void _mem_force_free( void *x ){
   free( mmt_mem_revert( x ) );
}
///end memory
///////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////
////binary-map for keys are uint32_t
///////////////////////////////////////////////////////////////////////////////
typedef struct node_uint32_struct{
	uint32_t key;
	void *   data;
   struct node_uint32_struct *left, *right;
}node_uint32_t;


static inline node_uint32_t *_create_node_uint32_t(uint32_t key, void *data){
	node_uint32_t *ret = (node_uint32_t *)malloc( sizeof( node_uint32_t) );
	ret->left  = NULL;
	ret->right = NULL;
	ret->key   = key;
	ret->data  = data;
	return ret;
}

static inline void *__get_map_uint32_t( node_uint32_t *node, uint32_t key ){
	if( unlikely( node == NULL ))
		return NULL;
	if( key < node->key )
		return __get_map_uint32_t( node->left, key );
	if( node->key < key )
		return __get_map_uint32_t( node->right, key );
	return node->data;
}

static inline void *__set_map_uint32_t( node_uint32_t **node_ptr, uint32_t key, void *data ){
	node_uint32_t *node = *node_ptr;

	if( node == NULL ){
		*node_ptr = _create_node_uint32_t( key, data );
		return data;
	}

	if( key < node->key )
		return __set_map_uint32_t( &node->left, key, data );
	if( node->key < key )
		return __set_map_uint32_t( &node->right, key, data );

	return node->data;
}

static inline void __free_map_uint32_t( node_uint32_t *node ){
	if( node == NULL ) return;

	__free_map_uint32_t( node->left );

	__free_map_uint32_t( node->right );

	free( node );
}

static inline void __iterate_map_uint32_t( node_uint32_t * node, void (*callback) (uint32_t key, void * value, void * args), void *args ){
	if( node == NULL ) return;

	__iterate_map_uint32_t( node->left, callback, args );

	callback( node->key, node->data, args );

	__iterate_map_uint32_t( node->right, callback, args );

}
///End binary-map
///////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////
///Memory pools
///////////////////////////////////////////////////////////////////////////////
typedef struct mem_pools_struct{
	size_t bytes_count; //total number of available bytes of all pools
	size_t   max_bytes;
	node_uint32_t *pools_map;
}mem_pools_t ;

static __thread mem_pools_t mem_pools = {
		.bytes_count = 0,
		.max_bytes   = 10000,
		.pools_map   = NULL
};

//malloc using mem_pools
static inline void *_pools_alloc( uint32_t elem_size ){
	mmt_mem_pool_t *pool = __get_map_uint32_t( mem_pools.pools_map, elem_size );
	if( unlikely( pool == NULL || pool->elements_count == 0 )){
		return _mem_alloc( elem_size );
	}

	//reduce number of available elements
	mem_pools.bytes_count -= elem_size;
	return mmt_mem_pool_allocate_element( pool, mmt_mem_alloc );
}

//free using mem_pools
static inline void _pools_free( void *elem ){
	mmt_memory_t *mem = mmt_mem_revert( elem );

	//total pools is full => free memory
	if( unlikely( mem_pools.bytes_count >= mem_pools.max_bytes )){
		free( mem );
		return;
	}

	//find a slot in set of pools to store this element
	mmt_mem_pool_t *pool = __get_map_uint32_t( mem_pools.pools_map, mem->size );

	//its pool does not exist or it is full
	//happen only one time when the pool for elem_size does not exist
	if( unlikely( pool == NULL )){
		pool = mmt_mem_pool_create( mem->size, 100 );
		//insert the pool into mem_pools
		__set_map_uint32_t( &mem_pools.pools_map, mem->size, pool );
	}

	//increase the total available bytes of the mem_pools
	mem_pools.bytes_count += mem->size;

	//store the element to the pool
	mmt_mem_pool_free_element( pool, elem, (void *)_mem_force_free );
}

static inline void _free_one_pool( uint32_t key, void *data, void *args){
	mmt_mem_pool_delete( (mmt_mem_pool_t *)data, _mem_force_free );
}

//free the mem_pools when app stopped
static inline void _free_mem_pools(){
	//free each pool of mem_pools
	__iterate_map_uint32_t( mem_pools.pools_map, _free_one_pool, NULL );
	//free tree_map
	__free_map_uint32_t(  mem_pools.pools_map );
}

static __attribute__((destructor)) void _destructor () {
	_free_mem_pools();
}
///End memory pools
///////////////////////////////////////////////////////////////////////////////


void *mmt_mem_alloc(size_t size){
#ifdef DEBUG_MODE
	mmt_assert( size > 0, "Size must be positive" );
#endif

	return _mem_alloc( size );
//	return _pools_alloc( size );
}

void mmt_mem_force_free( void *x ){
#ifdef DEBUG_MODE
	mmt_assert( x != NULL, "x (%p) must not be NULL", x );
#endif

	_mem_force_free( x );
//	return _pools_free( x );
}
