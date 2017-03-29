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
size_t free_message_ts( message_t *msg, uint16_t size );

static inline size_t free_message_t( message_t *msg ){
	return free_message_ts( msg, 1);
}

/**
 * Copy data to elem->data
 * @param msg
 * @param elem
 * @param data
 * @param length
 * @return
 */
int set_data_of_one_element_message_t( message_t *msg, message_element_t *elem, const void *data, size_t length );


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
