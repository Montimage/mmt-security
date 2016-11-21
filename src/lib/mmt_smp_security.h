/*
 * mmt_smp_security.h
 *
 *  Created on: Nov 17, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_LIB_MMT_SMP_SECURITY_H_
#define SRC_LIB_MMT_SMP_SECURITY_H_

#include "mmt_security.h"

typedef void mmt_smp_sec_handler_t;

/**
 * Register some rules to validate
 * - Input
 * 	+ rules_arr  : array of rules to be validated
 * 	+ rules_count: number of rules in #rules_arr
 * 	+ callback   : a function to be called when a rules is validated
 * 	+ user_data  : data will be passed to the #callback
 */
mmt_smp_sec_handler_t *mmt_smp_sec_register(
		const rule_info_t **rules_arr,
		size_t rules_count,
		uint8_t threads_count,
		mmt_sec_callback callback,
		void *user_data);

/**
 * Unregister, free resources
 */
void mmt_smp_sec_unregister( mmt_smp_sec_handler_t *handler, bool stop_immediatly );

/**
 * Give message to validate
 */
void mmt_smp_sec_process( const mmt_smp_sec_handler_t *handler, const message_t *message );

void mmt_smp_sec_stop( mmt_smp_sec_handler_t *handler, bool stop_immediatly  );

/**
 * Get rules attached to a given #handler
 */
size_t mmt_smp_sec_get_rules(  const mmt_smp_sec_handler_t *handler,  const rule_info_t ***rules_array );

/**
 * Get list of unique protocols and their attributes needed by the given #handler
 */
size_t mmt_smp_sec_get_unique_protocol_attributes( const mmt_smp_sec_handler_t *handler, const proto_attribute_t ***proto_atts_array );


#endif /* SRC_LIB_MMT_SMP_SECURITY_H_ */