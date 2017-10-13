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
#include "version.h"
#include "config.h"

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
 * It must be called from the thread that called #mmt_sec_init
 */
void mmt_sec_close( );


/**
 * This function create a new group consisting of several threads to process a set of rules.
 * - Input
 * 	+ threads_count: number of threads
 * 	+ core_mask    : a string indicating logical cores to be used,
 * 						  e.g., "1-8,11-12,19" => we use cores 1,2,..,8,11,12,19
 *    + rule_mask    : a string indicating special rules being attributed to special threads
 *    						e.g., "(1:10-13)(2:50)(4:1007-1010)"
 *    						The other rules will be attributed equally to the rest of threads.
 * 	+ callback     : a function to be called when a rules is validated
 * 	+ user_data    : data will be passed to the #callback
 * - Return a handler pointer
 * - Note:
 * 	The function callback can be called from different threads. (Thus if it accesses
 * 	to a global variable or a static one, the access to these variables must be synchronous)
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
 * Add new rules to a security handler.
 */
size_t mmt_sec_reload( mmt_sec_handler_t *handler, size_t threads_count, const uint32_t *cores_id, const char *rules_mask );
size_t mmt_sec_unregister_rules( mmt_sec_handler_t *handler, const char *rules_ranges );


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
        uint64_t val = t->tv_sec;
        return val * 1000000 + t->tv_usec;;
}

/**
 * Decode an uint64_t value to a #timeval
 */
static inline void mmt_sec_decode_timeval( uint64_t val, struct timeval *time ){
        time->tv_sec  = val / 1000000;     //timestamp: second
        time->tv_usec = val % 1000000 ; //timestamp: microsecond
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


#ifdef ADD_OR_RM_RULES_RUNTIME

/**
 * Remove a set of rules from processing
 * @param handler
 * @param rules_count
 * @param rules_id_set
 * @return number of rules being removed
 */
size_t mmt_security_remove_rules( mmt_sec_handler_t *handler, size_t rules_count, const uint32_t* rules_id_set );


/**
 * Add a set of rules to process
 * @param handler
 * @param rules_mask
 * @param update_if_existing
 * @return
 */
size_t mmt_security_add_rules( mmt_sec_handler_t *handler, const char *rules_mask, bool update_if_existing );
#endif

/**
 * Print information of the rules existing.
 */
void mmt_sec_print_rules_info();
#endif /* SRC_LIB_MMT_SECURITY_H_ */
