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
}message_t;



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

#endif /* SRC_LIB_MESSAGE_T_H_ */
