/*
 * mmt_security.h
 *
 *  Created on: Oct 10, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_LIB_MMT_SECURITY_H_
#define SRC_LIB_MMT_SECURITY_H_

#include "plugin_header.h"
#include "base.h"
#include "data_struct.h"
#include "../dpi/mmt_dpi.h"


/**
 * init mmt-security engine:
 * - load plugins (encoded rules)
 */
size_t mmt_sec_get_rules_info( const rule_info_t ***rules_array );

typedef void *mmt_sec_handler_t;

enum verdict_type {VERDICT_DETECTED, VERDICT_NOT_DETECTED, VERDICT_RESPECTED, VERDICT_NOT_RESPECTED, VERDICT_UNKNOWN};
static const char* verdict_type_string[] = {"detected", "not_detected", "respected", "not_respected", "unknown"};

/**
 * A function to be called when a rule is validated
 */
typedef void (*mmt_sec_callback)(
		const rule_info_t *rule,		//rule being validated
		enum verdict_type verdict,		//DETECTED, NOT_RESPECTED
		uint64_t timestamp,  			//moment (by time) the rule is validated
		uint32_t counter,					//moment (by order of packet) the rule is validated
		const mmt_map_t * const trace,//historic of messages that validates the rule
		void *user_data					//#user-data being given in mmt_sec_register_rules
		);

/**
 * Register some rules to validate
 * - Input
 * 	+ rules_arr  : array of rules to be validated
 * 	+ rules_count: number of rules in #rules_arr
 * 	+ callback   : a function to be called when a rules is validated
 * 	+ user_data  : data will be passed to the #callback
 */
mmt_sec_handler_t *mmt_sec_register(
		const rule_info_t **rules_arr,
		size_t rules_count,
		mmt_sec_callback callback,
		void *user_data);

/**
 * Unregister, free resources
 */
void mmt_sec_unregister( mmt_sec_handler_t *handler );

/**
 * Give message to validate
 */
void mmt_sec_process( const mmt_sec_handler_t *handler, const message_t *message );

/**
 * Get rules attached to a given #handler
 */
size_t mmt_sec_get_rules(  const mmt_sec_handler_t *handler,  const rule_info_t ***rules_array );

/**
 * Get list of unique protocols and their attributes needed by the given #handler
 */
size_t mmt_sec_get_unique_protocol_attributes( const mmt_sec_handler_t *handler, const proto_attribute_t ***proto_atts_array );

/**
 * Convert a given execution trace to a JSON string
 */
char* convert_execution_trace_to_json_string( const mmt_map_t *trace );

/**
 * Encode a #timeval to an uint64_t value
 */
static inline uint64_t mmt_sec_encode_timeval( const struct timeval *t ){
	uint64_t val = t->tv_sec * 1000000 + t->tv_usec;
	return val;
}

#endif /* SRC_LIB_MMT_SECURITY_H_ */
