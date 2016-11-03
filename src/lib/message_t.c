/*
 * message_t.c
 *
 *  Created on: Oct 20, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "message_t.h"
#include "mmt_lib.h"
#include "expression.h"

/**
 * Public API
 */
void free_message_t( message_t *msg ){
	size_t i;
	__check_null( msg,  );  // nothing to do

	//free message contains only when there is one reference to its father
	if( mmt_mem_reference_count( msg ) == 1 ){
		for( i=0; i<msg->elements_count; i++ )
			mmt_mem_free( msg->elements[i].data );

		mmt_mem_free( msg->elements );
	}
	mmt_mem_free( msg );
}

/**
 * public API
 */
message_t *retain_message_t( message_t *msg ){
	mmt_mem_retain( msg );
	return msg;
}
/**
 * Public API
 */
message_t *clone_message_t( const message_t *msg ){
	message_t *new_msg;
	size_t i;
	__check_null( msg, NULL );

	return retain_message_t( (message_t*)msg );
//
//	new_msg = mmt_mem_dup( msg, sizeof( message_t) );
//
//	new_msg->elements = mmt_mem_dup( msg->elements, sizeof( message_element_t ) * new_msg->elements_count );
//
//	for( i=0; i<new_msg->elements_count; i++ ){
//		if( msg->elements[ i ].data == NULL )
//			new_msg->elements[ i ].data = NULL;
//		else
//			new_msg->elements[ i ].data = mmt_mem_dup( msg->elements[ i ].data,
//					msg->elements[i].data_type == NUMERIC ? sizeof( double ) : strlen( (char *)msg->elements[ i ].data ) );
//	}
//
//	return new_msg;
}


