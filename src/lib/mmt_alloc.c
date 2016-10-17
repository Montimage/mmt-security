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

void mmt_mem_info( size_t *allocated, size_t *freed ){
	mmt_assert( allocated != NULL && freed != NULL, "Variables are NULL");
	*allocated = allocated_memory_size;
	*freed     = freed_memory_size;
}

void mmt_print_mem_info(){
	mmt_log(INFO, "MMT allocated: %zu bytes, freed: %zu bytes", allocated_memory_size, freed_memory_size );
}

void *mmt_malloc(size_t size){
	if( size == 0 ) return NULL;

	uint8_t * retval = (uint8_t *)malloc( sizeof( size_t ) + size + 1 );
	//quit if not enough
	mmt_assert( retval != NULL, "Not enough memory");
	//remember size of memory being allocated
	allocated_memory_size += size;

	//safe string
	retval[ sizeof( size_t ) + size ] = '\0';

	//store size to head of the memory segment
	*((size_t*) retval) = size;

	return (void*)( retval + sizeof( size_t ));
}


void *mmt_realloc( void *x, size_t size ){
   if( x == NULL ) {
      if( size == 0 ) return NULL; // nothing to do
      return mmt_malloc( size );
   }

   // x != NULL
   if( size == 0 ) {
      mmt_free( x );
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


void mmt_free( void *x ){
   if( x == NULL ) return; // nothing to do

   uint8_t *x0 = (uint8_t*)x - sizeof( size_t );
   freed_memory_size += *((size_t*)x0);
   free( x0 );
}

size_t mmt_mem_size( const void *x ){
   if( x == NULL ) return 0; // nothing to do

   uint8_t *x0 = (uint8_t*)x - sizeof( size_t );
   return *((size_t*) x0);
}

void* mmt_mem_concat( const void *ptr_1, const void *ptr_2 ){
	size_t s1, s2;
	void *ret;
	s1 = mmt_mem_size( ptr_1 );
	s2 = mmt_mem_size( ptr_2 );
	ret = mmt_malloc( s1 + s2 );
	memcpy( ret, ptr_1, s1 );
	memcpy( ret + s2, ptr_2, s2 );
	return ret;
}
