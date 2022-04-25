/*
 * mmt_bit256.h
 *
 *  Created on: Sep 6, 2018
 *          by: Huu Nghia Nguyen
 *
 * This file implements a set of bit operations on an array of 256 bit.
 */

#ifndef SRC_LIB_MMT_BIT_H_
#define SRC_LIB_MMT_BIT_H_

#include <stdint.h>
#include <stdbool.h>

#define MMT_BIT_NB_BYTES   32
#define MMT_BIT_LENGTH     (MMT_BIT_NB_BYTES*8)
typedef struct{
	uint8_t data[MMT_BIT_NB_BYTES]; //we need 32 bytes (256/8) to represent 256 bits
}mmt_bit_t;

static inline void mmt_bit_init( mmt_bit_t *b ){
	memset(b->data, 0, sizeof(mmt_bit_t));
}

static inline mmt_bit_t* mmt_bit_create(){
	 mmt_bit_t *b  = calloc( 1, sizeof( mmt_bit_t) );
	 return b;
}

static inline void mmt_bit_free( mmt_bit_t *b ){
	free( b );
}

/**
 * Set a bit on
 * @param b
 * @param index - index of bit to set
 */
static inline void mmt_bit_set( mmt_bit_t *b, uint8_t index ){
	uint8_t i = index >>  3; // index / 8
	uint8_t j = index  &  7; // index % 8
	b->data[i] |= (1 << j);
}

/**
 * Set a bit off
 * @param b
 * @param index - index of bit to set
 */
static inline void mmt_bit_clear( mmt_bit_t *b, uint8_t index ){
	uint8_t i = index >>  3; // index / 8
	uint8_t j = index  &  7; // index % 8
	b->data[i] &= ~(1 << j);
}

/**
 * Check value of a bit
 * @param b
 * @param index - index of bit to check
 */
static inline bool mmt_bit_check( const mmt_bit_t *b, uint8_t index ){
	uint8_t i = index >>  3; // index / 8
	uint8_t j = index  &  7; // index % 8

	return (b->data[i] & (1 << j));
}

/**
 * Check whether the value of (a & b) is zero
 * @param a
 * @param b
 * @return
 */
static inline bool mmt_bit_is_zero_and( const mmt_bit_t *a, const mmt_bit_t *b ){
	int i;
	for( i=0; i<MMT_BIT_NB_BYTES; i++ )
		if( (a->data[i] & b->data[i]) != 0 )
			return false;
	return true;
}

/**
 * Modify a by using OR operator its bits with the one of b
 * @param a
 * @param b
 */
static inline void mmt_bit_or( mmt_bit_t *a, const mmt_bit_t *b ){
	int i;
	for( i=0; i<MMT_BIT_NB_BYTES; i++ )
		a->data[i] |= b->data[i];
}

/**
 * Check whether the SET bits of pattern is a subset of SET bits of a, that is,
 *  all bit 1 in pattern are also SET on a
 * @param a
 * @param pattern
 * @return
 */
static inline bool mmt_bit_is_contain( const mmt_bit_t *a, const mmt_bit_t *pattern ){
	int i;
	for( i=0; i<MMT_BIT_NB_BYTES; i++ )
		if( (a->data[i] & pattern->data[i]) != pattern->data[i] )
			return false;
	return true;
}
#endif /* SRC_LIB_MMT_BIT_H_ */
