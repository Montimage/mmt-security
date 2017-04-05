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
#include "prefetch.h"

//
//static pthread_spinlock_t spin_lock;
//
//__attribute__((constructor)) void _constructor () {
//	mmt_assert( pthread_spin_init ( &spin_lock, 0 ) == 0, "Cannot init spinlock for message_t" );
//}
//

#define INIT_ID_VALUE 0

static __thread mmt_mem_pool_t *mem_pool = NULL;

message_t *create_message_t( size_t elements_length ){
	int i;
//	if( unlikely( mem_pool == NULL ))
//		mem_pool = mmt_mem_pool_create( sizeof( message_t ) + sizeof( message_element_t) * elements_length, 1000 );

	//add one element at the end to ensure any research will return at least one element
	//i.e., when we do not find an element having given proto_id and att_id, then the last
	elements_length ++;
	message_t *msg;
	size_t data_length =  get_config()->input.max_report_size;
//	msg = mmt_mem_pool_allocate_element( mem_pool, mmt_mem_alloc );
	msg = mmt_mem_alloc( sizeof( message_t ) + sizeof( message_element_t) * elements_length  + data_length );

	msg->elements_length = elements_length;
	msg->elements       = (message_element_t *) (&msg[1]); //store elements at the same date segment with msg
	for( i=0; i<msg->elements_length; i++ ){
		msg->elements[i].data     = NULL;
		msg->elements[i].proto_id = INIT_ID_VALUE;
		msg->elements[i].att_id   = INIT_ID_VALUE;
	}

	msg->_data_index  = 0;
	msg->_data        = &((uint8_t *) msg)[ sizeof( message_t ) + sizeof( message_element_t) * elements_length ];
	msg->_data_length = data_length;
	msg->elements_count = 0;
	return msg;
}


void force_free_message_t( message_t *msg ){
//	mmt_mem_pool_free_element( mem_pool, msg, mmt_mem_force_free );
	mmt_mem_force_free( msg );
}


size_t free_message_ts( message_t *msg, uint16_t size ){
	size_t ret;
	__check_null( msg, 0 );  // nothing to do

	mmt_memory_t *mem = mmt_mem_revert( msg );

	//free message only when there is no more reference to it
	if( mem->ref_count <= size ){
		mmt_mem_force_free( msg );
		return 0;
	}

	ret = __sync_sub_and_fetch( &mem->ref_count, size );

	return ret;
}



static inline message_element_t * _find_element( const message_t *msg, uint32_t proto_id, uint32_t att_id, bool swept ){
//	const uint64_t *key, *val;
	int i;
//	int low = 0, high = msg->elements_count - 1, mid = 0;

//	message_element_t key_struct;

//	if( msg->elements_count == 0 )
//		return & msg->elements[ msg->elements_count ];

	//encode proto_id and att_id into 64bits
//	key_struct.proto_id = proto_id;
//	key_struct.att_id   = att_id;
//
//	key = (uint64_t *) &key_struct.proto_id;


	for( i=0; i<msg->elements_count; i++ )
		if( msg->elements[ i ].att_id  == att_id && msg->elements[ i ].proto_id  == proto_id )
			break;

	return & msg->elements[ i ];

	//this is done by supposing that elements in #msg is sorteds by ascending of proto_id && att_id
//	while( low <= high ) {
//		mid = (low + high)/2;
//
//		// low path
//		prefetch_r (& msg->elements[(mid + 1 + high)/2], 1);
//		// high path
//		prefetch_r (& msg->elements[(low + mid - 1)/2],  1);
//
//		val = (uint64_t *) &msg->elements[ mid ].proto_id;
//
//		if( *val == *key)
//			return & msg->elements[ mid ] ;
//		else if( *val < *key)
//			low = mid + 1;
//		else// if( *val > key)
//			high = mid-1;
//	}
//
//	if( !swept )
//		//not found => return the first available element
//		return & msg->elements[ msg->elements_count ];
//
//
//	//We did not find any element in msg->elements that has proto_id.att_id
//	//=> we "insert" a element to a suitable position to ensure that the elements is an increased array
//
//	//push a high part of elements go forward 1 element
//	//so we can insert a new element for proto_id.att_id
//	for( i = msg->elements_count ; i>0; i--){
//
//		val = (uint64_t *) &msg->elements[ i-1 ].proto_id;
//		if( *val < *key )
//			break;
//
//		msg->elements[i] = msg->elements[ i-1 ];
//	}
//
//	return & msg->elements[ i ];
}

message_element_t * get_element_message_t( const message_t *msg, uint32_t proto_id, uint32_t att_id ){
	return _find_element( msg, proto_id, att_id, false );
}

const void *get_element_data_message_t( const message_t *msg, uint32_t proto_id, uint32_t att_id ){
	return _find_element( msg, proto_id, att_id, false )->data;
}


int set_element_data_message_t( message_t *msg, uint32_t proto_id, uint32_t att_id, const void *data, enum data_type data_type, size_t data_length ){
	mmt_memory_t *mem;
	message_element_t *el;
	int i;

	if( unlikely (msg->_data_index + data_length + SIZE_OF_MMT_MEMORY_T + 1 >= msg->_data_length )){
		mmt_warn( "Report for %d.%d is too big (%zu bytes), must increase config.input.max_report_size",
				proto_id, att_id, data_length + SIZE_OF_MMT_MEMORY_T);
		return MSG_OVERFLOW;
	}
	//do not need NULL
	else if( data_length == 0 || data == NULL ){
		return MSG_CONTINUE;
	}

	el = _find_element( msg, proto_id, att_id, true );

	if( el->proto_id != proto_id || el->att_id != att_id ){
		//msg has not yet contained proto_id && att_id
		//=> increase its number of elements
		msg->elements_count ++;

		el->proto_id = proto_id;
		el->att_id   = att_id;
	}

	el->data_type = data_type;

	//convert to mmt_memory_t
	mem = (mmt_memory_t *) &msg->_data[ msg->_data_index ];
	mmt_mem_reset( mem, data_length );

	el->data = mem->data;
	memcpy( el->data, data, data_length );

	msg->_data_index += data_length + SIZE_OF_MMT_MEMORY_T + 1;

	//update hash to mark the present of elem->data
	//msg->hash |= elem->proto_id | elem->att_id;

	return MSG_CONTINUE;
}

//__attribute__((destructor)) void _destructor () {
//	mmt_mem_pool_free( mem_pool );

//}
