/*
 * mmt_security.h
 *
 *  Created on: Oct 10, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 *  The functions in this file is not thread-free
 */

#ifndef SRC_LIB_MMT_SINGLE_SECURITY_H_
#define SRC_LIB_MMT_SINGLE_SECURITY_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "mmt_lib.h"
#include "plugin_header.h"
#include "mmt_array_t.h"
#include "verdict_printer.h"
#include "mmt_security.h"


typedef struct mmt_single_sec_handler_struct mmt_single_sec_handler_t;

/**
 * Register some rules to validate
 * - Input
 * 	+ rules_arr  : array of rules to be validated
 * 	+ rules_count: number of rules in #rules_arr
 * 	+ callback   : a function to be called when a rules is validated
 * 	+ user_data  : data will be passed to the #callback
 */
mmt_single_sec_handler_t *mmt_single_sec_register(
		rule_info_t const*const*rules_arr,
		size_t rules_count,
		bool verbose,
		mmt_sec_callback callback,
		void *user_data);

/**
 * Unregister, free resources
 */
size_t mmt_single_sec_unregister( mmt_single_sec_handler_t *handler );

/**
 * Give message to validate
 */
void mmt_single_sec_process( mmt_single_sec_handler_t *handler, message_t *message );

/**
 * Return number of messages being processed by this handler
 */
size_t mmt_single_sec_get_processed_messages( const mmt_single_sec_handler_t *handler );

#ifdef MODULE_ADD_OR_RM_RULES_RUNTIME
/**
 * Disable a set of rules that will be no more verified
 *
 * @return number of rules being disabled
 */
size_t mmt_single_sec_remove_rules( mmt_single_sec_handler_t *handler );

/**
 * Add a set of rules to verify
 * @param handler
 * @return number of rules being added
 */
size_t mmt_single_sec_add_rules( mmt_single_sec_handler_t *handler, size_t new_rules_count,
		const uint32_t *new_rules_id_arr );
#endif

#endif /* SRC_LIB_MMT_SINGLE_SECURITY_H_ */
