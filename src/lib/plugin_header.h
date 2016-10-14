/*
 * gen_fsm_header.h
 *
 *  Created on: 7 oct. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 *  This is header of a plugin generated by main_gen_plugin.
 *  A plugin contains the encoding of one or many rules.
 */

#ifndef SRC_LIB_PLUGIN_HEADER_H_
#define SRC_LIB_PLUGIN_HEADER_H_
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
	void *data;
}message_element_t;

typedef struct message_struct{
	uint32_t counter;
	uint64_t timestamp;
	size_t elements_count;
	message_element_t **elements;
}message_t;


/**
 * Information of a rule in generated lib
 */
typedef struct rule_info_struct{
	uint32_t id;
	uint8_t events_count;
	char *description;
	char *if_satisfied;
	char *if_not_satisfied;

	//return a FSM instance
	void* (* create_instance )();
	//return a struct using by guard of FSM above, e.g., _msg_t_1
	void* (* convert_message )( const message_t *);
	/**
	 * - Return:
	 * 	+ An array (size #events_count) of number.
	 */
	const void* (* hash_message )( const void * );
}rule_info_t;

/**
 * Get information of rules in generated library
 * - Output
 * 	+ rules_arr
 * - Return
 * 	+ number of rules
 */
size_t mmt_sec_get_plugin_info( const rule_info_t **plugins_arr );


#endif /* SRC_LIB_PLUGIN_HEADER_H_ */