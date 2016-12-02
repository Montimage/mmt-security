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

/**
 *
 */
typedef struct message_element_struct{
	uint32_t proto_id;
	uint32_t att_id;
	int data_type; //NUMERIC, STRING
	void *data;
}message_element_t;


typedef struct message_struct{
	uint64_t counter;
	uint64_t timestamp;
	size_t elements_count;
	message_element_t *elements;
}message_t;

/**
 * Create a new message from data
 * The result message is a continuous memory segment.
 * - Input:
 * 	+ data:
 * 	+ len : length of #data
 * - Return:
 * 	+ NULL if data is mal-formatted
 * 	+ a pointer of type #message_t
 */
message_t *parse_message_t( const uint8_t *data, uint32_t len );

/**
 * Clone a message_t.
 * This function creates new message_t by cloning everything inside #msg.
 */
message_t *clone_message_t( const message_t *msg );

/**
 * Free a message_t
 * This function reduces the number of references of #msg.
 * If there does not exist any more any references to #msg, then
 * its resource will be freed.
 *
 * One can increase number of references of a variable by using either
 * #mmt_mem_retain or #mmt_mem_retains
 */
size_t free_message_t( message_t *msg );

#endif /* SRC_LIB_MESSAGE_T_H_ */
