/*
 * mmt_mem_pool.c
 *
 *  Created on: Jan 30, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "mmt_mem_pool.h"

typedef struct _mmt_mem_pool_struct{
	mmt_mem_pool_t pool;
	uint32_t head_index, tail_index;
	void **data;
}_mmt_mem_pool_t;


mmt_mem_pool_t * mmt_mem_pool_create( size_t element_size, size_t max_elements_count ){
	_mmt_mem_pool_t *ret = malloc( sizeof( _mmt_mem_pool_t ) );
	if( ret == NULL )
		return NULL;

	ret->pool.element_size       = element_size;
	ret->pool.elements_count     = 0;
	ret->pool.max_elements_count = max_elements_count;
	ret->head_index = 0;
	ret->tail_index = 0;
	ret->data       = malloc(  sizeof( void *) * ret->pool.max_elements_count );

	if( ret->data == NULL ){
		free( ret );
		return NULL;
	}
	return (mmt_mem_pool_t *) ret;
}

void mmt_mem_pool_reset( mmt_mem_pool_t *pool){
	_mmt_mem_pool_t *_pool = (_mmt_mem_pool_t *) pool;
	_pool->head_index    = 0;
	_pool->tail_index    = 0;
	pool->elements_count = 0;
}

void mmt_mem_pool_delete( mmt_mem_pool_t *pool, void (*free_fn)(void *) ){
	_mmt_mem_pool_t *_pool;
	//free also its data
	if( free_fn != NULL ){
		_pool = (_mmt_mem_pool_t *) pool;
		while( pool->elements_count > 0 ){
			free_fn( _pool->data[ _pool->head_index ] );
			_pool->head_index = ( _pool->head_index + 1 ) % pool->max_elements_count;
			pool->elements_count --;
		}
	}

	free( ((_mmt_mem_pool_t *) pool)->data );
	free( pool );
}

void * mmt_mem_pool_allocate_element( mmt_mem_pool_t * pool, void *(*malloc_fn)(size_t)){
	void *ret;
	_mmt_mem_pool_t *_pool;
	if( pool->elements_count == 0 )
		return malloc_fn( pool->element_size );
	else{
		_pool = (_mmt_mem_pool_t *) pool;
		pool->elements_count --;
		ret = _pool->data[ _pool->head_index ];
		_pool->head_index = ( _pool->head_index + 1 ) % pool->max_elements_count;
		return ret;
	}
}

void mmt_mem_pool_free_element( mmt_mem_pool_t *pool, void * elem, void (*free_fn)(void *)){
	_mmt_mem_pool_t *_pool;
	//pool is full
	if( pool->elements_count == pool->max_elements_count )
		free_fn( elem );
	else{
		_pool = (_mmt_mem_pool_t *) pool;
		pool->elements_count ++;
		_pool->data[ _pool->tail_index ] = elem;
		_pool->tail_index = ( _pool->tail_index + 1 ) % pool->max_elements_count;
	}
}
