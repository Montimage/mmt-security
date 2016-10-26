/*
 * mmt_alloc.c
 *
 *  Created on: 19 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */
#include <stdint.h>
#include "mmt_alloc.h"
#include "mmt_log.h"

static size_t allocated_memory_size, freed_memory_size;

typedef struct _memory_struct{
	size_t ref_count;
	size_t  size;
	void *  data;
}_memory_t;

const static size_t size_of_memory_t = sizeof( _memory_t );

#define _convert_mem( x ) (_memory_t *) ( (uint8_t*)x - size_of_memory_t )

/**
 * Public API
 */
void mmt_mem_info( size_t *allocated, size_t *freed ){
	mmt_assert( allocated != NULL && freed != NULL, "Variables are NULL");
	*allocated = allocated_memory_size;
	*freed     = freed_memory_size;
}

void mmt_mem_print_info(){
	mmt_log(INFO, "MMT allocated: %zu bytes, freed: %zu bytes", allocated_memory_size, freed_memory_size );
}

void *mmt_mem_alloc(size_t size){
	if( size == 0 ) return NULL;
	size = size_of_memory_t + size + 1;
	_memory_t *mem = malloc( size );

	//quit if not enough
	mmt_assert( mem != NULL, "Not enough memory");
	//remember size of memory being allocated
	allocated_memory_size += size;

	//safe string
	((char *)mem)[ size-1 ] = '\0';

	//mem->data points to the memory segment after sizeof( _memory_t )
	mem->data = mem + 1;
	//store size to head of the memory segment
	mem->size      = size;
	mem->ref_count = 1;

	return mem->data;
}


void *mmt_mem_realloc( void *x, size_t size ){
	mmt_halt( "Does not support properly %s:%d", __FILE__, __LINE__ );
   if( x == NULL ) {
      if( size == 0 ) return NULL; // nothing to do
      return mmt_mem_alloc( size );
   }

   // x != NULL
   if( size == 0 ) {
      mmt_mem_free( x );
      return NULL;
   }

   // ( x != NULL ) && ( size != 0 )
   uint8_t *x0 = (uint8_t*)x - sizeof( size_t );
   size_t  psz = *((size_t*)x0);

   uint8_t *x1 = (uint8_t*)realloc( x0, size + sizeof( size_t ));

   mmt_assert( x1 != NULL, "not enough memory" );

   //set new size
   *((size_t*)x1) = size;
   allocated_memory_size  += ( size - psz );

   return (void*)( x1 + sizeof( size_t ));
}


void mmt_mem_free( void *x ){
   if( x == NULL ) return; // nothing to do
   _memory_t *mem = _convert_mem( x );
   if( mem->ref_count <= 1 ){
		freed_memory_size += mem->size;
		free( mem );
   }else
   	mem->ref_count --;
}

void *mmt_mem_retain( void *x ){
   if( x == NULL ) return NULL; // nothing to do
   _memory_t *mem = _convert_mem( x );
   mem->ref_count ++;
   return mem->data;
}

size_t mmt_mem_size( const void *x ){
   if( x == NULL ) return 0; // nothing to do
   _memory_t *mem = _convert_mem( x );
   return mem->size;
}

size_t mmt_mem_reference_count( void *x ){
	if( x == NULL ) return 0; // nothing to do
	_memory_t *mem = _convert_mem( x );
	return mem->ref_count;
}

void* mmt_mem_concat( const void *ptr_1, const void *ptr_2 ){
	size_t s1, s2;
	void *ret;
	s1 = mmt_mem_size( ptr_1 );
	s2 = mmt_mem_size( ptr_2 );
	ret = mmt_mem_alloc( s1 + s2 );
	memcpy( ret, ptr_1, s1 );
	memcpy( ret + s2, ptr_2, s2 );
	return ret;
}
