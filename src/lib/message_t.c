/*
 * message_t.c
 *
 *  Created on: Oct 20, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "message_t.h"
#include "mmt_lib.h"
#include "expression.h"
#include "prefetch.h"
#include "mmt_security.h"


#define INIT_ID_VALUE 0
static __aligned mmt_memory_t *_memory = NULL;

message_t *create_message_t(){
	int i;
	const proto_attribute_t **proto_atts;
	message_t *msg;
	size_t _message_size;

	//create a reserved memory segment and initialize it
	//this is done only one time
	if( unlikely( _memory == NULL )){
		size_t elements_length = mmt_sec_get_unique_protocol_attributes( &proto_atts );

		size_t data_length =  mmt_sec_get_config( MMT_SEC__CONFIG__INPUT__MAX_MESSAGE_SIZE );
		data_length  += elements_length * SIZE_OF_MMT_MEMORY_T;
		_message_size = sizeof( message_t )	//message
						+ sizeof( message_element_t) * elements_length //elements
						+ data_length //data
					;
		msg = mmt_mem_alloc( _message_size );
		//elements
		msg->elements_count = elements_length;
		msg->elements        = (message_element_t *) (&msg[1]); //store elements at the same date segment with msg
		//for each element
		for( i=0; i<msg->elements_count; i++ ){
			msg->elements[i].data     = NULL;
			msg->elements[i].proto_id = INIT_ID_VALUE;
			msg->elements[i].att_id   = INIT_ID_VALUE;
		}

		msg->hash         = 0;
		msg->_data_index  = 0;
		msg->_data        = &((uint8_t *) msg)[ sizeof( message_t ) + sizeof( message_element_t) * elements_length ];
		msg->_data_length = data_length;

		_memory = mmt_mem_revert( msg );
	}


	//clone the reserved memory
	msg = mmt_mem_force_dup( _memory->data, _memory->size );
	//update data pointers
	msg->elements = (message_element_t *)( msg + 1 );
	msg->_data    = &((uint8_t *) msg)[ sizeof( message_t ) + sizeof( message_element_t) * msg->elements_count ];

	return msg;
}


void force_free_message_t( message_t *msg ){
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


message_element_t * get_element_message_t( const message_t *msg, uint32_t proto_id, uint32_t att_id ){
	int index = mmt_sec_hash_proto_attribute( proto_id, att_id );

#ifdef DEBUG_MODE
	if( unlikely( index >= msg->elements_count )){
		mmt_error("Access to outside message's elements");
		return NULL;
	}
#endif

	return &msg->elements[ index ];
}

const void *get_element_data_message_t( const message_t *msg, uint16_t index ){

#ifdef DEBUG_MODE
	if( unlikely( index >= msg->elements_count )){
		mmt_error("Access to outside message's elements");
		return NULL;
	}
#endif

	return msg->elements[ index ].data;
}


int set_element_data_message_t( message_t *msg, uint32_t proto_id, uint32_t att_id, const void *data, enum data_type data_type, size_t data_length ){
	mmt_memory_t *mem;
	message_element_t *el;
	int index;

	if( unlikely (msg->_data_index + data_length + SIZE_OF_MMT_MEMORY_T + 1 >= msg->_data_length )){
		mmt_warn( "Report %"PRIu64" for %d.%d is too big (req. %zu, avail. %d bytes), must increase \"%s\"",
				msg->counter,
				proto_id, att_id, data_length + SIZE_OF_MMT_MEMORY_T, msg->_data_length - msg->_data_index,
				mmt_sec_get_config_name( MMT_SEC__CONFIG__INPUT__MAX_MESSAGE_SIZE ));
		return MSG_OVERFLOW;
	}
	//do not need NULL
	else if( unlikely( data_length == 0 || data == NULL )){
		return MSG_CONTINUE;
	}

	index = mmt_sec_hash_proto_attribute( proto_id, att_id );

#ifdef DEBUG_MODE
	if( unlikely( index >= msg->elements_count )){
		mmt_error("Access to outside message's elements");
		return MSG_CONTINUE;
	}
#endif

	//update hash to mark the present of elem->data
	BIT_SET( msg->hash, index );

	el = & msg->elements[ index ];

	el->proto_id  = proto_id;
	el->att_id    = att_id;
	el->data_type = data_type;

	//convert to mmt_memory_t
	mem = (mmt_memory_t *) &msg->_data[ msg->_data_index ];
	mmt_mem_reset( mem, data_length );
	el->data = mem->data;

	memcpy( el->data, data, data_length );

	msg->_data_index += data_length + SIZE_OF_MMT_MEMORY_T + 1;

	return MSG_CONTINUE;
}

__attribute__((destructor)) void _destructor_message_t () {
	if( _memory )
		mmt_mem_free( _memory->data );
}
