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
#include <ctype.h>
#include "mmt_alloc.h"
#include "mmt_log.h"

#define str_end_with( str, y) (strcmp(str + strlen(str) - strlen( y ), y) == 0)
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


/**
 * Encode 2 uint16_t to 1 uint32_t
 */
static inline uint32_t simple_hash_32( uint16_t a, uint16_t b ){
	uint32_t val = 0;
	val = a << 16;
	val = val | b;
	return val;
}

/**
 * Decode 1 uint32_t to 2 uint16_t
 */
static inline void simple_dehash_32( uint32_t val, uint16_t *a, uint16_t *b){
	*a = val >> 16;
	*b = (val << 16) >> 16;
}



/**
 * Split a string to an array
 * @param string
 * @param a_delim
 * @param array
 * @return
 */
static inline size_t str_split(const char* string, char a_delim, char ***array){
	char *a_str = strdup( string );
	size_t count     = 0;
	char* tmp        = a_str;
	char* last_comma = NULL;
	char **result    = NULL;
	char delim[2];
	delim[0] = a_delim;
	delim[1] = 0;

	/* Count how many elements will be extracted. */
	while( *tmp ){
		if (a_delim == *tmp){
			count++;
			last_comma = tmp;
		}
		tmp++;
	}

	/* Add space for trailing token. */
	count += last_comma < (a_str + strlen(a_str) - 1);

	result = mmt_mem_alloc( sizeof( char* ) * count );

	size_t idx  = 0;

	char* token = strtok( a_str, delim );
	while( token ){
		result[ idx++ ] = mmt_mem_dup( token, strlen( token) );
		token = strtok( NULL, delim );
	}

	*array = result;

	free( a_str );
	return count;
}



/**
 * mask is a string indicating logical cores to be used,
 *  e.g., "1-8,11-12,19" => we use cores 1,2,..,8,11,12,19
 *
 * BNFesque
 * rangelist := (range | number) [',' rangelist]
 * range := number '-' number
 *
 * - Input:
 * 	+ mask is a string ended by '\0'
 * - Output:
 * 	+ an array is created
 * - Return:
 * 	+ size of the output array
 */
static inline size_t expand_number_range( const char *mask, uint8_t **result ){
	const char *cur, *prv;
	size_t size = 0, i, j;
	uint8_t num;
	uint8_t array[ 1000 ];

	*result = NULL;
	if( mask == NULL ) return 0;

	cur = mask;
	while( *cur != '\0' ){
		//first number
		if( !isdigit( *cur ) ){
			mmt_halt( "Core mask: Expected a digit at %s", cur );
			return 0;
		}

		num = atoi( cur );
		if( find_byte( num, array, size ) == 0 )
			array[ size++ ] = num;

		while( isdigit( *cur ) ) cur ++;


		if( *cur == '\0' ) break;

		//separator
		if( *cur != ',' &&  *cur != '-' ){
			mmt_halt( "Core mask: Expected a separator, either ' or , at %s", cur );
			return 0;
		}

		//second number
		if( *cur == '-' ){
			cur ++;
			num = atoi( cur );
			while( isdigit( *cur ) ) cur ++;

			i=array[ size-1 ] + 1;

			if( i > num ){
				mmt_halt( "Core mask: Range is incorrect %zu-%d", i-1, num );
				return 0;
			}

			for(  ; i<=num; i++ )
				if( find_byte( i, array, size ) == 0 )
					array[ size ++ ] = i;

			//after the second number must be ',' or '\n'
			if( *cur == '\0' )
				break;
		}

		if( *cur != ',' ){
			mmt_halt( "Core mask: Expected a separator , at %s", cur );
			return 0;
		}
		cur++;

		if( *cur == '\0' ){
			mmt_halt( "Core mask: Unexpected a separator , at the end" );
			return 0;
		}
	}

	*result = mmt_mem_dup( array, size );
	return size;
}
#endif /* SRC_LIB_MMT_UTILS_H_ */
