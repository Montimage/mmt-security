/*
 * gen_fsm_header.h
 *
 *  Created on: 7 oct. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_LIB_GEN_FSM_HEADER_H_
#define SRC_LIB_GEN_FSM_HEADER_H_
#include <stdint.h>
#include <sys/time.h>

/**
 * Information of a rule in generated lib
 */
typedef struct rule_info_struct{
	size_t id;
	char *description;
	char *if_satisfied;
	char *if_not_satisfied;
}rule_info_t;

/**
 * Get information of rules in generated library
 * - Output
 * 	+ rules_arr
 * - Return
 * 	+ number of rules
 */
size_t mmt_sec_get_rules_information( const rule_info_t **rules_arr );


typedef struct mmt_sec_handler_struct{
}mmt_sec_handler_t;

/**
 * A function to be called when a rule is validated
 */
typedef void (*mmt_sec_callback)(
		uint32_t rule_id,				//id of rule
		struct timeval timestamp,  //moment the rule is validated

		void *user_data				//#user-data being given in mmt_sec_register_rules
		);

/**
 * Register some rules to validate
 */
const mmt_sec_handler_t *mmt_sec_register_rules(
		const size_t *rules_id,
		size_t rules_count,
		mmt_sec_callback callback,
		void *user_data);


/**
 * Unregister, free
 */
void mmt_sec_unregister( mmt_sec_handler_t *handler );

typedef struct message_element_struct{
	uint32_t proto_id;
	uint32_t attr_id;
	uint32_t data_len;
	void *data;
}message_element_t;

typedef struct message_struct{
	uint32_t counter;
	struct timeval timestamp;
	size_t elements_count;
	message_element_t *elements;
}message_t;

void mmt_sec_process( const mmt_sec_handler_t *handler, const message_t *message );

#endif /* SRC_LIB_GEN_FSM_HEADER_H_ */
