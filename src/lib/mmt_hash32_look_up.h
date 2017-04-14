/*
 * mmt_hash32_look_up.h
 *
 *  Created on: Apr 10, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@me.com>
 */

#ifndef SRC_LIB_MMT_HASH32_LOOK_UP_H_
#define SRC_LIB_MMT_HASH32_LOOK_UP_H_

#include "mmt_lib.h"

////////////////////////////////////////////////////////////////////////////////
//simple hash table
////////////////////////////////////////////////////////////////////////////////
typedef struct mmt_hash_32_struct{
	uint32_t size;
	uint32_t count;
	uint32_t *keys;
	uint16_t *index;
}mmt_hash_32_t;

#define NO_KEY 0
#define MMT_HASH_32_FULL       -1
#define MMT_HASH_32_NOT_FOUND  -2
/**
 * This hash table is used for looking at most #size keys
 * @param size
 * @return
 */
static inline mmt_hash_32_t mmt_hash_32_create( uint32_t size ){
	int i;
	mmt_hash_32_t *h = mmt_mem_alloc( sizeof( mmt_hash_32_t ) + sizeof( uint32_t) * size  + sizeof( uint16_t) * size );
	h->size   = size;
	h->count  = 0;
	h->keys   = (uint32_t *) ( h + 1 );
	h->index  = (uint16_t *) ( ((char*)h->keys) + sizeof( uint32_t) * size );
	for( i=0; i<h->size; i++ ){
		h->keys[ i ]  = NO_KEY;
		h->index[ i ] = NO_KEY;
	}
	return h;
}

static inline void mmt_hash_32_free( mmt_hash_32_t *h ){
	mmt_mem_free( h );
}

static inline int mmt_hash32_hash( mmt_hash_32_t *h, uint32_t key, bool set ){
	int i = index = key % h->size;

	//collision
	while( h->keys[ i ] != NO_KEY ){
		if( h->keys[i] == key )
			return h->index[ i ];

		i ++;

		switch( i ){
		case h->count: //ring
			i = 0;
			break;
		case index:
			return MMT_HASH_32_FULL;
		}
	}

	if( !set )
		return MMT_HASH_32_NOT_FOUND;

	h->keys[ i ]  = key ;
	h->index[ i ] = h->count;
	h->count ++;
	return h->index[ i ];
}

#endif /* SRC_LIB_MMT_HASH32_LOOK_UP_H_ */
