/*
 * message_t.h
 *
 *  Created on: Oct 20, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_LIB_MESSAGE_T_H_
#define SRC_LIB_MESSAGE_T_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include "mmt_lib.h"
#include "expression.h"

/**
 *
 */
typedef struct message_element_struct{
	uint32_t proto_id;
	uint32_t att_id;
	int data_type; //NUMERIC, STRING, VOID
	void *data;
}message_element_t;


typedef struct message_struct{
	uint64_t counter;
	uint64_t timestamp;
	size_t elements_count;
	message_element_t *elements;

	uint64_t hash;
	//for internal usage
	uint8_t *_data;
	size_t _data_index; //index of data
	size_t _data_length;
}message_t;

#define MSG_OVERFLOW 1

message_t *create_message_t( size_t elements_count );

void force_free_message_t( message_t *msg );

/**
 * Free a message_t
 * This function reduces the number of references of #msg.
 * If there does not exist any more any references to #msg, then
 * its resource will be freed.
 *
 * One can increase number of references of a variable by using either
 * #mmt_mem_retain or #mmt_mem_retains
 */
static inline size_t free_message_ts( message_t *msg, uint16_t size ){
	size_t ret;
	__check_null( msg, 0 );  // nothing to do

	mmt_memory_t *mem = mmt_mem_revert( msg );

	ret = __sync_sub_and_fetch( &mem->ref_count, size );

	//free message only when there is no more reference to it
	if( ret == 0 )
		force_free_message_t( msg );

	return ret;
}

static inline size_t free_message_t( message_t *msg ){
	return free_message_ts( msg, 1);
}

static inline int set_data_of_one_element_message_t( message_t *msg, message_element_t *elem, const void *data, size_t length ){
	mmt_memory_t *mem;
	if( unlikely (msg->_data_index + length + SIZE_OF_MMT_MEMORY_T  >= msg->_data_length )){
		mmt_warn( "Report for %d.%d is too big (%zu bytes), must increase config.input.max_report_size",
				elem->proto_id, elem->att_id,
				length + SIZE_OF_MMT_MEMORY_T);
		return MSG_OVERFLOW;
	}else if( length == 0 ){
		elem->data = NULL;
		return 0;
	}

	//convert to mmt_memory_t
	mem = (mmt_memory_t *) &msg->_data[ msg->_data_index ];
	mmt_mem_reset( mem, length );

	elem->data = mem->data;
	memcpy( elem->data, data, length );

	msg->_data_index += length + SIZE_OF_MMT_MEMORY_T;

	return 0;
}



/**
 * Convert data encoded by mmt-dpi to one element of message_t.
 * - Input:
 * 	+ data    : data to be converted
 * 	+ type    : type of #data
 * - Output:
 * 	+ el  : element to be updated in message_t
 * 	+ msg : message containing el
 * - return:
 * 	+ 0 if success
 */
int set_dpi_data_to_one_element_message_t( const void *data, int data_type, message_t *msg, message_element_t *el );


#endif /* SRC_LIB_MESSAGE_T_H_ */
