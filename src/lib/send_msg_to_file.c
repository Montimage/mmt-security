#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <pthread.h>
#include "mmt_lib.h"

#define MAX_FILE_NAME_LEN 500

static FILE *file       = NULL;
static char file_name[ MAX_FILE_NAME_LEN ] = {0};
static uint16_t period  = 5;   //period to create a new file
static time_t timestamp = 0;	   //the moment the current file was created

static pthread_mutex_t mutex_lock;

/**
 * args: file:///home/toto/data/:5
 */
void init_file(const char *filename, int period_sample ) {
	char str[ MAX_FILE_NAME_LEN ] = {0};
	int len = 0;

	strcpy( file_name, filename );
	period = period_sample;

	pthread_mutex_init( &mutex_lock, NULL );

	if( period == 0 ){
		len = snprintf( str, MAX_FILE_NAME_LEN, "%ssecurity.csv", file_name );
		str[ len ] = '\0';

		file = fopen( str, "w" );
		if( unlikely( file == NULL) )
			mmt_halt( "%d creation of \"%s\" failed: %s\n" , errno , str, strerror( errno ) );
	}

}

void close_file(){
	if( file != NULL )
		fclose( file );

	pthread_mutex_destroy( &mutex_lock );
}

void send_message_to_file( const char * message ) {
	char str[ MAX_FILE_NAME_LEN + 1] = {0};
	int len;
	time_t now = time( 0 );

	if( period > 0 ){
		//check to create sample file
		//lock
		if( pthread_mutex_lock( &mutex_lock) != 0 ){
			mmt_warn("Cannot lock");
			return;
		}

		//create a new file if need
		if( now - timestamp > period || file == NULL ){
			//close the current file if it is opening
			if( file != NULL ){
				//close .csv file
				fclose( file );

				//create semaphore for the current file
				len = snprintf( str, MAX_FILE_NAME_LEN, "%ssec-%ld.csv.sem", file_name, timestamp );
				str[ len ] = '\0';
				file = fopen( str, "w" );
				if( unlikely( file == NULL) )
					mmt_halt( "%d creation of \"%s\" failed: %s\n" , errno , str , strerror( errno ) );
				else
					fclose( file );
			}

			//create new csv file
			timestamp = now;

			len = snprintf( str, MAX_FILE_NAME_LEN, "%ssec-%ld.csv", file_name, timestamp );
			str[ len ] = '\0';

			file = fopen( str, "w" );
			if( unlikely( file == NULL) )
				mmt_halt( "%d creation of \"%s\" failed: %s\n" , errno , str , strerror( errno ) );
		}

		//unlock
		while( pthread_mutex_unlock( &mutex_lock) != 0 );
	}

	fprintf( file, "%s\n", message );
}

//end report message
