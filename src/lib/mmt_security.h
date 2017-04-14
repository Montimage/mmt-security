/*
 * security.h
 *
 *  Created on: Mar 17, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_LIB_MMT_SECURITY_H_
#define SRC_LIB_MMT_SECURITY_H_

#include "mmt_lib.h"
#include "plugin_header.h"
#include "mmt_array_t.h"
#include "verdict_printer.h"

typedef struct mmt_sec_handler_struct mmt_sec_handler_t;

enum verdict_type {VERDICT_DETECTED, VERDICT_NOT_DETECTED, VERDICT_RESPECTED, VERDICT_NOT_RESPECTED, VERDICT_UNKNOWN};
static const char* verdict_type_string[] = {"detected", "not_detected", "respected", "not_respected", "unknown"};

/**
 * A function to be called when a rule is validated
 */
typedef void (*mmt_sec_callback)(
		const rule_info_t *rule,		//rule being validated
		enum verdict_type verdict,		//DETECTED, NOT_RESPECTED
		uint64_t timestamp,  			//moment (by time) the rule is validated
		uint64_t counter,					//moment (by order of packet) the rule is validated
		const mmt_array_t * const trace,//historic of messages that validates the rule
		void *user_data					//#user-data being given in mmt_sec_register_rules
		);


/**
 * This function init globally mmt-security
 * It must be called from main thread before any register_security
 * @return
 */
int mmt_sec_init( const char *excluded_rules_id );

/**
 * This function closes globally mmt-security
 * It must be called from main thread
 */
void mmt_sec_close( );


/**
 *
 * @param thread_count
 * @param cores_mask
 * @param rule_mask
 * @param verbose
 * @param callback
 * @param user_data
 * @return
 */
mmt_sec_handler_t* mmt_sec_register( size_t threads_count, const uint32_t *cores_id, const char *rules_mask,
		bool verbose, mmt_sec_callback callback, void *user_data );


/**
 * Give message to validate
 */
void mmt_sec_process( mmt_sec_handler_t *handler, message_t *msg );

/**
 * Stop and free security handler
 * @param
 * @return number of alerts being generated
 */
size_t mmt_sec_unregister( mmt_sec_handler_t* );

/**
 * Get version information of smp-security
 * @return
 */
const char* mmt_sec_get_version_info();


/**
 * init mmt-security engine:
 * - load plugins (encoded rules)
 */
size_t mmt_sec_get_rules_info( const rule_info_t ***rules_array );


/**
 * Get list of unique protocols and their attributes needed by the given #handler
 */
size_t mmt_sec_get_unique_protocol_attributes( const proto_attribute_t ***proto_atts_array );

/**
 * Return an unique number representing the pair proto_id and att_id
 * @param proto_id
 * @param att_id
 * @return
 */
uint16_t mmt_sec_hash_proto_attribute( uint32_t proto_id, uint32_t att_id );

/**
 * Encode a #timeval to an uint64_t value
 */
static inline uint64_t mmt_sec_encode_timeval( const struct timeval *t ){
	uint64_t val = t->tv_sec * 1000000 + t->tv_usec;
	return val;
}

/**
 * Decode an uint64_t value to a #timeval
 */
static inline void mmt_sec_decode_timeval( uint64_t val, struct timeval *time ){
	time->tv_sec  = val / 1000000;     //timestamp: second
	time->tv_usec = val - time->tv_sec * 1000000 ; //timestamp: microsecond
}

/**
 * Print verdicts to the verdict printer that will send the verdicts to files or redis bus.
 * This function is called each time a verdict being detected.
 *
 * To use this, the verdict printer must be initiated before
 */
void mmt_sec_print_verdict( const rule_info_t *rule,		//id of rule
		enum verdict_type verdict,
		uint64_t timestamp,  //moment the rule is validated
		uint64_t counter,
		const mmt_array_t *const trace,
		void *user_data );


const char* mmt_convert_execution_trace_to_json_string( const mmt_array_t *trace, const rule_info_t *rule );


/**
 * Print information of the rules existing.
 */
void mmt_sec_print_rules_info();
#endif /* SRC_LIB_MMT_SECURITY_H_ */
