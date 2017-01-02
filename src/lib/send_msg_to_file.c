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

#define MAX_FILE_NAME_LEN 5000

static FILE *file       = NULL;
static char file_name[ MAX_FILE_NAME_LEN ] = {0};
static uint16_t period  = 5;   //period to create a new file
static time_t timestamp = 0;	 //the moment the current file was created

static pthread_mutex_t mutex_lock;

static void (*send_message_fn)(const char *) = NULL;

void send_message_to_file( const char *msg ){
	send_message_fn( msg );
}

static inline void close_current_file_and_create_semaphore(){
	char str[ MAX_FILE_NAME_LEN + 1] = {0};
	int len;
	if( file != NULL ){
		//close .csv file
		fclose( file );

		//create semaphore for the current file
		len = snprintf( str, MAX_FILE_NAME_LEN, "%ssec-%ld-%d.csv.sem", file_name, timestamp, (int)getpid() );
		str[ len ] = '\0';
		file = fopen( str, "w" );
		if( unlikely( file == NULL) )
			mmt_halt( "%d creation of \"%s\" failed: %s\n" , errno , str , strerror( errno ) );
		else
			fclose( file );

		file = NULL;
	}
}


static inline void send_message_to_single_file( const char * message ) {
	fprintf( file, "%s\n", message );
}

static inline void send_message_to_sampled_file( const char * message ) {
	char str[ MAX_FILE_NAME_LEN + 1] = {0};
	int len, ret;
	time_t now = time( 0 );

	//check to create sample file
	//lock
	ret = pthread_mutex_lock( &mutex_lock );
	if( ret != 0 ){
		mmt_warn("Error %d: Cannot lock file while writing", ret );
		return;
	}

	//create a new file if need
	if( now - timestamp >= period || file == NULL ){
		//close the current file if it is opening
		close_current_file_and_create_semaphore();

		//create new csv file
		timestamp = now;

		len = snprintf( str, MAX_FILE_NAME_LEN, "%ssec-%ld-%d.csv", file_name, timestamp, (int)getpid() );
		str[ len ] = '\0';

		file = fopen( str, "a" );
		if( unlikely( file == NULL) )
			mmt_halt( "%d creation of \"%s\" failed: %s\n" , errno , str , strerror( errno ) );
	}
	send_message_to_single_file( message );

	//unlock
	while( pthread_mutex_unlock( &mutex_lock) != 0 );
}



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
		len = snprintf( str, MAX_FILE_NAME_LEN, "%smmt-security-%d.csv", file_name, (int)getpid() );
		str[ len ] = '\0';

		file = fopen( str, "w" );
		if( unlikely( file == NULL) )
			mmt_halt( "%d creation of \"%s\" failed: %s\n" , errno , str, strerror( errno ) );

		send_message_fn = send_message_to_single_file;
	}else
		send_message_fn = send_message_to_sampled_file;

}


void close_file(){
	close_current_file_and_create_semaphore();

	pthread_mutex_destroy( &mutex_lock );
}


void reset_file(){
	close_current_file_and_create_semaphore();
	timestamp = 0;
}

//end report message
