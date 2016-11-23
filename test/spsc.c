/*
 * spsc.c
 *
 *  Created on: Nov 22, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */


#include "../src/lib/mmt_lib.h"
#include "../src/lib/lock_free_spsc_ring.h"
#include <pthread.h>
#include <time.h>
#include "../src/lib/system_info.h"

void *_consumer_fn( void *arg ){
	size_t total = 0, i;
	lock_free_spsc_ring_t *ring = (lock_free_spsc_ring_t * ) arg;
	void *ptr;
	int ret;
	do{
		do{
			ret = ring_pop( ring, &ptr );
			if( likely( ret == RING_SUCCESS ))
				break;
			else
				ring_wait_for_pushing( ring );
		}while( 1 );

		if( likely (ptr != NULL ))
			total += ( size_t )ptr;
		else
			break;

		//small calculation
		for( i=0; i<1000; i++ ) total += i;

	}while( 1 );
	mmt_info("Thread %d: %zu", gettid(), total );
	return NULL;
}

int main( int argc, char **args ){
	size_t consumers_count = 2;
	size_t loops_count     = 1*1000*1000;
	size_t ring_size       = 1000;
	size_t i,j;
	lock_free_spsc_ring_t **rings;
	pthread_t *p_ids;
	int ret;

	if( argc > 1 )
		consumers_count = atoll( args[ 1 ] );
	if( argc > 2 )
		loops_count     = atoll( args[ 2 ] );
	if( argc > 3 )
		ring_size       = atoll( args[ 3 ] );
	mmt_info( "Usage: %s consumers_count loops_count ring_size", args[ 0 ] );
	mmt_info( "Number of online processors: %ld", get_number_of_online_processors() );

	mmt_info( "Running %zu loops with 1 producer and %zu consumers. Size of each ring is %zu",
			loops_count, consumers_count, ring_size );

	rings = mmt_mem_alloc( sizeof( void *) * consumers_count );
	for( i=0; i< consumers_count; i++ )
		rings[ i ] = ring_init( ring_size );

	p_ids = mmt_mem_alloc( sizeof( pthread_t ) * consumers_count );

	time_t start = time(NULL);
	for( i=0; i< consumers_count; i++ )
		mmt_assert( pthread_create( &(p_ids[i]), NULL, _consumer_fn, rings[ i ] ) == 0,
				"Cannot create thread %zu", i );

	//fix the main thread on cpu[0]
	if( move_the_current_thread_to_a_processor( 0, -15 ) )
			mmt_error("Error on moving the current thread to cpu[0]");

	//producer
	for( j=0; j<loops_count; j++ ){
		for( i=0; i< consumers_count; i++ ){
			do{
				ret = ring_push( rings[ i ], (void *) (j + 1) );
				if( likely( ret == RING_SUCCESS ))
					break;
				else
					ring_wait_for_poping( rings[ i ] );
			}while( 1 );
		}
	}

	//insert NULL to exit consumers
	for( i=0; i< consumers_count; i++ ){
		do{
			ret = ring_push( rings[ i ], NULL );
			if( likely( ret == RING_SUCCESS ))
				break;
			else
				ring_wait_for_poping( rings[ i ] );
		}while( 1 );
	}

	//waiting for the consumers finish
	for( i=0; i< consumers_count; i++ )
		pthread_join( p_ids[i], NULL );

	start = time(NULL) - start;

	printf("%.2f\n", (double)start );

	for( i=0; i< consumers_count; i++ )
		ring_free( rings[ i ] );
	mmt_mem_free( rings );
	mmt_mem_free( p_ids );
	return 0;
}

