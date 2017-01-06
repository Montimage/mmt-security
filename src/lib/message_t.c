/*
 * message_t.c
 *
 *  Created on: Oct 20, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "message_t.h"
#include "mmt_lib.h"
#include "expression.h"

#include <pthread.h>
//
//static pthread_spinlock_t spin_lock;
//
//__attribute__((constructor)) void _constructor () {
//	mmt_assert( pthread_spin_init ( &spin_lock, 0 ) == 0, "Cannot init spinlock for message_t" );
//}
//
//__attribute__((destructor)) void _destructor () {
//	pthread_spin_destroy ( &spin_lock );
//}

inline message_t *parse_message_t( const uint8_t *data, uint32_t len ){
	message_t *msg = (message_t *) mmt_mem_dup( data, len );

	return msg;
}

inline message_t *create_message_t( size_t elements_count ){
	message_t *msg;
	msg = mmt_mem_alloc( sizeof( message_t ) + sizeof( message_element_t) * elements_count );
	msg->elements_count = elements_count;
	msg->elements       = (message_element_t *) (&msg[1]); //store elements at the same date segment with msg
	return msg;
}

/**
 * Public API
 */
inline size_t free_message_t( message_t *msg ){
	size_t i, ret;
	__check_null( msg, 0 );  // nothing to do
	mmt_memory_t *mem = mmt_mem_revert( msg );

	ret = __sync_fetch_and_sub( &mem->ref_count, 1);

	//free message only when there is one reference to its father
	if( ret == 1 ){
		for( i=0; i<msg->elements_count; i++ )
			if( likely( msg->elements[i].data != NULL && msg->elements[i].data_type != VOID ))
				mmt_mem_force_free( msg->elements[i].data );

		mmt_mem_force_free( msg );
		return 0;
	}
	else if( ret < 1 ){
		return 0;
	}else
		return ret;
}

inline message_t *retain_message_t( message_t *msg ){
	__check_null( msg, NULL );
	mmt_memory_t *mem = mmt_mem_revert( msg );
	__sync_add_and_fetch( &mem->ref_count, 1);

	return mem->data;
}


inline message_t *retain_many_message_t( message_t *msg, size_t count ){
	__check_null( msg, NULL );
	mmt_memory_t *mem = mmt_mem_revert( msg );
	__sync_add_and_fetch( &mem->ref_count, count );

	return mem->data;
}


/**
 * Public API
 */
message_t *clone_message_t( const message_t *msg ){
	__check_null( msg, NULL );
	size_t i;
	message_t *new_msg;

	new_msg = mmt_mem_dup( msg, sizeof( message_t) );

	new_msg->elements = mmt_mem_dup( msg->elements, sizeof( message_element_t ) * new_msg->elements_count );

	for( i=0; i<new_msg->elements_count; i++ ){
		if( msg->elements[ i ].data == NULL || msg->elements[i].data_type == VOID  )
			new_msg->elements[ i ].data = msg->elements[ i ].data;
		else
			new_msg->elements[ i ].data = mmt_mem_dup( msg->elements[ i ].data,
					msg->elements[i].data_type == NUMERIC ? sizeof( double ) : strlen( (char *)msg->elements[ i ].data ) );
	}

	return new_msg;
}


