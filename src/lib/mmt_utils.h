/*
 * mmt_utils.h
 *
 *  Created on: 22 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_LIB_MMT_UTILS_H_
#define SRC_LIB_MMT_UTILS_H_

#include <stdlib.h>
#include <stdint.h>
/**
 * find a byte in an array
 * - Return
 * 	+ 0 if does not exist
 * 	+ otherwise index+1 where index is the position of search in the array
 */
static inline size_t find_byte( uint8_t search, const uint8_t *data, size_t size){
	size_t i;
	for( i=0; i<size; i++ )
		if( data[i] == search )
			return i+1;
	return 0;
}

#endif /* SRC_LIB_MMT_UTILS_H_ */
