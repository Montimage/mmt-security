/*
 * mmt_bit.h
 *
 *  Created on: Oct 10, 2017
 *      Author: nhnghia
 */

#ifndef SRC_LIB_MMT_BIT_H_
#define SRC_LIB_MMT_BIT_H_

#define MMT_BIT_SIZE (64*5)
#define MMT_BIT_TYPE uint64_t[ 4 ]
/**
 * Set all bits to zero
 */
#define MMT_BIT_FILL_ZERO( x )  do{ x[0] = 0; x[1] = 0; x[2] = 0; x[3] = 0; x[4] = 0; } while( 0 )
/**
 * Set all bits to one
 */
#define MMT_BIT_FILL_ONE ( x )  do{ x[0] = 0xFFFFFFFFFFFFFFFF; x[1] = 0; x[2] = 0; x[3] = 0; x[4] = 0; } while( 0 )

#define MMT_BIT_SET(   var, index )  ( var[ index / 64 ] |= (1 << (index % 64)) )
#define MMT_BIT_CLEAR( var, index )  ( var[ index / 64 ] &= ~(1 << (index % 64)) )
#define MMT_BIT_AND( x, y ) ((x[0] & y[0]) | (x[1] & y[1]) | (x[2] & y[2]) | (x[2] & y[2]) | (x[3] & y[3]) | (x[4] & y[4]) )


#endif /* SRC_LIB_MMT_BIT_H_ */
