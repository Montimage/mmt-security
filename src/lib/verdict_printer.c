/*
 * verdict_printer.c
 *
 *  Created on: Dec 19, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include <stdlib.h>
#include <string.h>
#include "verdict_printer.h"
#include "mmt_lib.h"

#define DEFAULT_REDIS_PORT    6379

#define MAX_STRING_LEN 500

void init_redis();
void send_message_to_redis(const char*);

void init_file();
void send_message_to_file(const char*);
void close_file();

enum output_mode{
	OUTPUT_NONE  = 0,
	OUTPUT_REDIS = 1,	/**< Output to redis server */
	OUTPUT_FILE  = 2, /**< Output to file */
};

static enum output_mode output_mode = OUTPUT_NONE;

/**
 * - Redis: redis://192.168.0.10:6379
 * - File : file:///home/toto/data/:5
 */
void verdict_printer_init( const char *file_string, const char *redis_string ){
	char *pos = NULL;
	int len   = 0, val = 0;
	char str[ MAX_STRING_LEN ] = {0};

	//output to file
	if( file_string != NULL && file_string[0] != '\0' ){
		pos = strchr( file_string, ':');
		//no period being provided => use default
		if( pos == NULL )
			init_file( file_string, 0 );
		else{
			len = pos - file_string;
			mmt_assert(len < MAX_STRING_LEN, "Max length of file name is %d", MAX_STRING_LEN );

			strncpy( str, file_string, len );
			str[ len ] = '\0';

			//jump over filename
			file_string += len + 1;
			val = atoll( file_string );
			init_file( str, val );
		}

		output_mode |= OUTPUT_FILE;
	}

	//output to redis
	if( redis_string != NULL && redis_string[0] != '\0' ){
			pos = strchr( redis_string, ':');
			//no period being provided => use default
			if( pos == NULL )
				init_redis( redis_string, DEFAULT_REDIS_PORT );
			else{
				len = pos - redis_string;
				mmt_assert(len < MAX_STRING_LEN, "Max length of file name is %d", MAX_STRING_LEN );
				strncpy( str, redis_string, len );
				str[ len ] = '\0';

				//jump over hostname
				redis_string += len + 1;
				val = atoll( redis_string );
				init_redis( str, val );
			}

			output_mode |= OUTPUT_REDIS;
		}
}

void verdict_printer_send( const char* msg ){
	//and bit
	if( output_mode & OUTPUT_FILE )
		send_message_to_file( msg );

	//and bit
	if( output_mode & OUTPUT_REDIS )
		send_message_to_redis( msg );
}


void verdict_printer_free( ){
	if( output_mode & OUTPUT_FILE )
		close_file();
}
