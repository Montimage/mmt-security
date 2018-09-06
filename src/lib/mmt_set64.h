/*
 * mmt_set64.h
 *
 *  Created on: Sep 6, 2018
 *          by: Huu Nghia Nguyen
 *
 * This file implements a set containing elements of 64 bytes.
 * The set supports basically 3 operations:
 * (1) add a number.
 * (2) remove a number.
 * (3) check whether the set contains a number.
 */

#ifndef SRC_LIB_MMT_SET64_H_
#define SRC_LIB_MMT_SET64_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "mmt_bit256.h"

typedef struct{
	mmt_bit256_t data[8]; //we need 8 blocks to represent 8 bytes of 64 bit numbers
}mmt_set64_t;


static inline mmt_set64_t* mmt_set64_create(){
	mmt_set64_t *ret = calloc(1, sizeof( mmt_set64_t ));
	return ret;
}

static inline void mmt_set64_free( mmt_set64_t *set ){
	free( set );
}

/**
 * Add a number to the set
 * @param set
 * @param val
 */
static inline void mmt_set64_add( mmt_set64_t *set, uint64_t val ){
	uint8_t *p = (uint8_t *) &val;
	mmt_bit256_set( &set->data[0], p[0] );
	mmt_bit256_set( &set->data[1], p[1] );
	mmt_bit256_set( &set->data[2], p[2] );
	mmt_bit256_set( &set->data[3], p[3] );
	mmt_bit256_set( &set->data[4], p[4] );
	mmt_bit256_set( &set->data[5], p[5] );
	mmt_bit256_set( &set->data[6], p[6] );
	mmt_bit256_set( &set->data[7], p[7] );
}

/**
 * Check whether the set contains a number
 * @param set
 * @param val
 * @return
 */
static inline bool mmt_set64_check( mmt_set64_t *set, uint64_t val ){
	uint8_t *p = (uint8_t *) &val;
	bool ret = (
			mmt_bit256_check( &set->data[0], p[0] )
	&& mmt_bit256_check( &set->data[1], p[1] )
	&& mmt_bit256_check( &set->data[2], p[2] )
	&& mmt_bit256_check( &set->data[3], p[3] )
	&& mmt_bit256_check( &set->data[4], p[4] )
	&& mmt_bit256_check( &set->data[5], p[5] )
	&& mmt_bit256_check( &set->data[6], p[6] )
	&& mmt_bit256_check( &set->data[7], p[7] )
	);
	return ret;
}

/**
 * Remove a number from the set.
 * The function is always success even if the number  does not exist.
 * @param set
 * @param val
 */
static inline void mmt_set64_rm( mmt_set64_t *set, uint64_t val ){
	uint8_t *p = (uint8_t *) &val;
	mmt_bit256_clear( &set->data[0], p[0] );
	mmt_bit256_clear( &set->data[1], p[1] );
	mmt_bit256_clear( &set->data[2], p[2] );
	mmt_bit256_clear( &set->data[3], p[3] );
	mmt_bit256_clear( &set->data[4], p[4] );
	mmt_bit256_clear( &set->data[5], p[5] );
	mmt_bit256_clear( &set->data[6], p[6] );
	mmt_bit256_clear( &set->data[7], p[7] );
}


#endif /* SRC_LIB_MMT_SET64_H_ */
