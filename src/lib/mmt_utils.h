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
#include <time.h>
#include "mmt_alloc.h"
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

/**
 * Get current data-time in a string.
 * - Input:
 * 	+ #template is the one of #strftime, for example: "%d %m %Y %H:%M"
 * - Note:
 * 	You need to use #mmt_free to free the returned result.
 */
static inline char* get_current_date_time_string( const char *template ){
	char text[100];
	time_t now = time(NULL);
	struct tm *t = localtime(&now);

	strftime(text, sizeof(text)-1, template, t);
	return mmt_mem_dup( text, strlen( text ));
}
#endif /* SRC_LIB_MMT_UTILS_H_ */
