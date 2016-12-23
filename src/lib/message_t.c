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

message_t *parse_message_t( const uint8_t *data, uint32_t len ){
	message_t *msg = (message_t *) mmt_mem_dup( data, len );

	return msg;
}

/**
 * Public API
 */
size_t free_message_t( message_t *msg ){
	size_t i, ret;
	__check_null( msg, 0 );  // nothing to do

	//pthread_spin_lock( &spin_lock );
	//free message only when there is one reference to its father
	if( mmt_mem_reference_count( msg ) <= 1 ){
		for( i=0; i<msg->elements_count; i++ )
			if( msg->elements[i].data != NULL && msg->elements[i].data_type != VOID )
				mmt_mem_free( msg->elements[i].data );

		mmt_mem_free( msg->elements );
		mmt_mem_free( msg );
		ret = 0;
	}
	else
		ret = mmt_mem_free( msg );
	//pthread_spin_unlock( &spin_lock );

	return ret;
}

/**
 * Public API
 */
message_t *clone_message_t( const message_t *msg ){
	message_t *new_msg;
	size_t i;
	__check_null( msg, NULL );

//	pthread_spin_lock( &spin_lock );
//	new_msg = mmt_mem_retain( (void *) msg );
//	pthread_spin_unlock( &spin_lock );
//	return new_msg;

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


