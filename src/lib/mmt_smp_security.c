/*
 * mmt_smp_security.c
 *
 *  Created on: Nov 17, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "base.h"
#include "mmt_lib.h"
#include <pthread.h>
#include "mmt_smp_security.h"
#include <unistd.h>
#include "system_info.h"
#include "lock_free_spsc_ring.h"

#define RING_SIZE 100000

//implemented in mmt_security.c
void _mmt_sec_process( const mmt_sec_handler_t *handler, message_t *msg );

typedef struct _mmt_smp_sec_handler_struct{
	size_t threads_count;

	size_t rules_count;
	const rule_info_t **rules_array;

	mmt_sec_handler_t **mmt_sec_handlers;
	pthread_t *threads_id;

	size_t proto_atts_count;
	const proto_attribute_t **proto_atts_array;

	//one buffer per thread
	lock_free_spsc_ring_t **messages_buffers;

}_mmt_smp_sec_handler_t;

struct _thread_arg{
	size_t index;
	mmt_sec_handler_t *mmt_sec;
	lock_free_spsc_ring_t *ring;
};

/**
 * Public API
 */
size_t mmt_smp_sec_get_rules(  const mmt_smp_sec_handler_t *handler, const rule_info_t ***rules_array ){
	__check_null( handler, 0 );
	_mmt_smp_sec_handler_t *_handler = (_mmt_smp_sec_handler_t *) handler;

	*rules_array = _handler->rules_array;
	return _handler->rules_count;
}


/**
 * Public API
 */
size_t mmt_smp_sec_get_unique_protocol_attributes( const mmt_smp_sec_handler_t *handler, const proto_attribute_t ***proto_atts_array ){
	__check_null( handler, 0 );

	_mmt_smp_sec_handler_t *_handler = (_mmt_smp_sec_handler_t *) handler;

	*proto_atts_array = _handler->proto_atts_array;
	return _handler->proto_atts_count;
}

/**
 * Public API
 */
void mmt_smp_sec_unregister( mmt_sec_handler_t *handler, bool stop_immediately ){
	size_t i;
	__check_null( handler, );

	_mmt_smp_sec_handler_t *_handler = (_mmt_smp_sec_handler_t *)handler;

	mmt_smp_sec_stop( handler, stop_immediately );

	//free data elements of _handler
	for( i=0; i<_handler->threads_count; i++ )
		mmt_sec_unregister( _handler->mmt_sec_handlers[i] );

	for( i=0; i<_handler->threads_count; i++ )
		ring_free( _handler->messages_buffers[ i ] );

	mmt_mem_free( _handler->messages_buffers );

	mmt_mem_free( _handler->mmt_sec_handlers );
	mmt_mem_free( _handler->threads_id );

	mmt_mem_free( _handler->proto_atts_array );
	mmt_mem_free( _handler );
}


static inline void *_process_one_thread( void *arg ){
	struct _thread_arg *thread_arg = (struct _thread_arg *) arg;
	mmt_sec_handler_t *mmt_sec     = thread_arg->mmt_sec;
	lock_free_spsc_ring_t *ring    = thread_arg->ring;

	void **arr;
	size_t size, i;
	long cpus_count = get_number_of_online_processors() - 1;

	pthread_setcanceltype( PTHREAD_CANCEL_ENABLE, NULL );

	if( cpus_count > 1 )
		if( move_the_current_thread_to_a_processor( thread_arg->index % cpus_count + 1, -10 )) //cpu[0] is used for dispatching
			mmt_warn("Cannot set affinity of thread %d on cpu[%ld]", gettid(), thread_arg->index % cpus_count + 1  );

	while( 1 ){

		size = ring_pop_brust( ring, &arr );

		if( size == 0 )
			ring_wait_for_pushing( ring );
		else{

			//do not process the last msg in the for
			size -= 1;
			for( i=0; i< size; i++ ){
				_mmt_sec_process( mmt_sec, arr[i] );
			}

			//only the last msg can be NULL
			if( unlikely( arr[ size ] == NULL ) ){
				mmt_mem_free( arr );
				break;
			}else{
				_mmt_sec_process( mmt_sec, arr[size] );
			}

			mmt_mem_free( arr );
		}
	}

	mmt_mem_free( thread_arg );

	return NULL;
}

/**
 * Public API
 */
mmt_smp_sec_handler_t *mmt_smp_sec_register( const rule_info_t **rules_array, size_t rules_count, uint8_t threads_count,
		mmt_sec_callback callback, void *user_data){
	size_t i, j, rules_count_per_thread;
	mmt_sec_handler_t *mmt_sec_handler;
	const proto_attribute_t **p_atts;
	const rule_info_t **rule_ptr;
	int ret;
	struct _thread_arg *thread_arg;

	__check_null( rules_array, NULL );

	//number of threads <= number of rules
	if( rules_count < threads_count ){
		mmt_warn( "Number of threads is greater than number of rules (%d > %zu). Use %zu threads.", threads_count, rules_count, rules_count );
		threads_count = rules_count;
	}

	_mmt_smp_sec_handler_t *handler = mmt_mem_alloc( sizeof( _mmt_smp_sec_handler_t ));

	handler->rules_count     = rules_count;
	handler->rules_array     = rules_array;
	handler->threads_count   = threads_count;
	handler->messages_buffers= mmt_mem_alloc( sizeof( void *) * handler->threads_count );

	//this is only for get mmt_sec_get_unique_protocol_attributes
	mmt_sec_handler = mmt_sec_register( rules_array, rules_count, NULL, NULL );
	handler->proto_atts_count = mmt_sec_get_unique_protocol_attributes( mmt_sec_handler, &p_atts );
	handler->proto_atts_array = mmt_mem_dup( p_atts, sizeof( void *) * handler->proto_atts_count );
	mmt_sec_unregister( mmt_sec_handler ); //free this handler after getting unique set of proto_atts
	mmt_sec_handler = NULL;
	//end of using #mmt_sec_handler

	//one buffer per thread
	for( i=0; i<handler->threads_count; i++)
		handler->messages_buffers[ i ] = ring_init( RING_SIZE );

	handler->mmt_sec_handlers = mmt_mem_alloc( sizeof( mmt_sec_handler_t *) * handler->threads_count );
	rule_ptr = rules_array;

	//each handler manages #rules_count_per_thread
	//e.g., if we have 10 rules and 3 threads
	// => each thread will manage 3 rules unless the last thread manages 4 rules
	for( i=0; i<handler->threads_count; i++ ){
		rules_count_per_thread = rules_count / threads_count;

#ifdef DEBUG_MODE
		printf("Thread %2zu processes %zu rules:", i, rules_count_per_thread );
		for( j=0; j<rules_count_per_thread; j++ )
			printf(" %d%c", rule_ptr[j]->id, j == rules_count_per_thread - 1? '\n':',' );
#endif

		handler->mmt_sec_handlers[ i ] = mmt_sec_register( rule_ptr, rules_count_per_thread, callback, user_data );

		rule_ptr    += rules_count_per_thread;
		rules_count -= rules_count_per_thread; //number of remaining rules
		threads_count --;//number of remaining threads
	}

	handler->threads_id = mmt_mem_alloc( sizeof( pthread_t ) * handler->threads_count );
	for( i=0; i<handler->threads_count; i++ ){
		thread_arg          = mmt_mem_alloc( sizeof( struct _thread_arg ));
		thread_arg->index   = i;
		thread_arg->mmt_sec = handler->mmt_sec_handlers[ i ];
		thread_arg->ring    = handler->messages_buffers[ i ];
		ret = pthread_create( &handler->threads_id[ i ], NULL, _process_one_thread, thread_arg );
		mmt_assert( ret == 0, "Cannot create thread %zu", (i+1) );
	}

	if( move_the_current_thread_to_a_processor(0, -15 ) )
		mmt_warn("Cannot set affinity of thread %d on cpu[0]", gettid() );

	return (mmt_smp_sec_handler_t *)handler;
}

/**
 * Public API
 */
void mmt_smp_sec_process( const mmt_smp_sec_handler_t *handler, const message_t *message ){
	_mmt_smp_sec_handler_t *_handler;
	int ret;
	message_t *msg = clone_message_t( message );
	lock_free_spsc_ring_t **ring;
	__check_null( handler, );

	_handler = (_mmt_smp_sec_handler_t *)handler;

	for( ring = _handler->messages_buffers; ring < &(_handler->messages_buffers[ _handler->threads_count ]); ring++ ){
		//insert msg to a buffer
		msg = retain_message_t( msg );
		do{
			ret = ring_push( *ring, msg );

			if( likely( ret == RING_SUCCESS ))
				break;
			else
				ring_wait_for_poping( *ring );
		}while( 1 );
	}
}


void mmt_smp_sec_stop( mmt_smp_sec_handler_t *handler, bool stop_immediately  ){
	size_t i;
	__check_null( handler, );

	_mmt_smp_sec_handler_t *_handler = (_mmt_smp_sec_handler_t *)handler;

	if( stop_immediately ){
		for( i=0; i<_handler->threads_count; i++ )
			pthread_cancel( _handler->threads_id[ i ] );
	}else{
		mmt_smp_sec_process( handler, NULL );

		//waiting for all threads finish their job
		for( i=0; i<_handler->threads_count; i++ )
			pthread_join( _handler->threads_id[ i ], NULL );
	}
}
