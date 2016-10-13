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

/**
 * init mmt-security engine:
 * - load plugins (encoded rules)
 */
size_t mmt_sec_get_rules_info( const rule_info_t ***rules_array );

typedef void *mmt_sec_handler_t;

/**
 * A function to be called when a rule is validated
 */
typedef void (*mmt_sec_callback)(
		uint32_t rule_id,		//id of rule
		uint64_t timestamp,  //moment the rule is validated

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

#endif /* SRC_LIB_MMT_SECURITY_H_ */
