/*
 * message_t.c
 *
 *  Created on: Oct 20, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "message_t.h"
#include "mmt_lib.h"
#include "expression.h"
#include "mmt_mem_pool.h"

//
//static pthread_spinlock_t spin_lock;
//
//__attribute__((constructor)) void _constructor () {
//	mmt_assert( pthread_spin_init ( &spin_lock, 0 ) == 0, "Cannot init spinlock for message_t" );
//}
//


//static mmt_mem_pool_t *mem_pool = NULL;

inline message_t *parse_message_t( const uint8_t *data, uint32_t len ){
	message_t *msg = (message_t *) mmt_mem_dup( data, len );

	return msg;
}

message_t *create_message_t( size_t elements_count ){
//	if( unlikely( mem_pool == NULL ))
//		mem_pool = mmt_mem_pool_create( sizeof( message_t ) + sizeof( message_element_t) * elements_count, 1000 );

	message_t *msg;

	//msg = mmt_mem_pool_allocate_element( mem_pool, mmt_mem_alloc );
	msg = mmt_mem_alloc( sizeof( message_t ) + sizeof( message_element_t) * elements_count );

	msg->elements_count = elements_count;
	msg->elements       = (message_element_t *) (&msg[1]); //store elements at the same date segment with msg
	return msg;
}


void force_free_message_t( message_t *msg ){
	size_t i;
	for( i=0; i<msg->elements_count; i++ )
		if( likely( msg->elements[i].data != NULL ))
			mmt_mem_force_free( msg->elements[i].data );

	//mmt_mem_pool_free_element( mem_pool, msg, mmt_mem_force_free );
	mmt_mem_force_free( msg );
}

__attribute__((destructor)) void _destructor () {
//	mmt_mem_pool_free( mem_pool );
}

