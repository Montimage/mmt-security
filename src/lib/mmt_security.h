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
#include "mmt_dpi.h"

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
		const rule_info_t *rule,		//rule being verified
		enum verdict_type verdict,
		uint64_t timestamp,  //moment the rule is validated
		uint32_t counter,
		const mmt_map_t *trace,
		void *user_data		//#user-data being given in mmt_sec_register_rules
		);

/**
 * Register some rules to validate
 */
mmt_sec_handler_t *mmt_sec_register(
		const rule_info_t **rules_arr,
		size_t rules_count,
		mmt_sec_callback callback,
		void *user_data);

/**
 * Unregister, free
 */
void mmt_sec_unregister( mmt_sec_handler_t *handler );

void mmt_sec_process( const mmt_sec_handler_t *handler, const message_t *message );

size_t mmt_sec_get_rules(  const mmt_sec_handler_t *handler,  const rule_info_t ***rules_array );

size_t mmt_sec_get_unique_protocol_attributes( const mmt_sec_handler_t *handler, const proto_attribute_t ***proto_atts_array );

char* convert_execution_trace_to_json_string( const mmt_map_t *trace );

static inline uint64_t mmt_sec_encode_timeval( const struct timeval *t ){
	uint64_t val = t->tv_sec * 1000000 + t->tv_usec;
	return val;
}

#endif /* SRC_LIB_MMT_SECURITY_H_ */
