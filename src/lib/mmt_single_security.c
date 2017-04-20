/*
 * mmt_security.c
 *
 *  Created on: Oct 10, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <math.h>

#include "base.h"
#include "mmt_lib.h"

#include "mmt_fsm.h"
#include "plugins_engine.h"
#include "rule_verif_engine.h"
#include "expression.h"
#include "rule.h"
#include "version.h"
#include "plugin_header.h"

#include "../dpi/types_defs.h"
#include "../dpi/mmt_dpi.h"
#include "mmt_single_security.h"


struct mmt_single_sec_handler_struct{
	size_t rules_count;
	const rule_info_t **rules_array;
	//this is called each time we reach final/error state
	mmt_sec_callback callback;
	//a parameter will give to the #callback
	void *user_data_for_callback;
	rule_engine_t **engines;

	//number of generated alerts
	size_t *alerts_count;

	//an array of #rules_count elements having type of uint64_t
	//each element represents required data of one rule
	uint64_t *rules_hash;

	//a hash number is combination of #rules_hash
	uint64_t hash;

	//number of messages processed
	size_t messages_count;

	bool verbose;
};


/**
 * Public API
 */
mmt_single_sec_handler_t *mmt_single_sec_register( const rule_info_t **rules_array, size_t rules_count, bool verbose,
		mmt_sec_callback callback, void *user_data){
	int i, j, index;
	const rule_engine_t *engine;
	const rule_info_t *rule;
	const proto_attribute_t *p;
	uint32_t max_instance_count = get_config()->security.max_instances;
	__check_null( rules_array, NULL );

	mmt_single_sec_handler_t *handler = mmt_mem_alloc( sizeof( mmt_single_sec_handler_t ));
	handler->rules_count = rules_count;
	handler->rules_array = rules_array;
	handler->callback    = callback;
	handler->user_data_for_callback = user_data;
	handler->alerts_count = mmt_mem_alloc( sizeof (size_t ) * rules_count );
	handler->verbose      = verbose;
	handler->hash         = 0;
	handler->rules_hash   = mmt_mem_alloc( sizeof( uint64_t ) * rules_count );
	//one fsm for one rule
	handler->engines = mmt_mem_alloc( sizeof( void *) * rules_count );
	for( i=0; i<rules_count; i++ ){
		rule = rules_array[i];

		handler->engines[i]      = rule_engine_init( rule, max_instance_count );
		handler->alerts_count[i] = 0;

		//hash of a rule is combination of hashes of its events
		handler->rules_hash[i]   = 0;
		engine = handler->engines[i];
		for( j=0; j<engine->events_count; j++ )
			handler->rules_hash[i] |= engine->events_hash[ j ];

		//a combination of #rules_hash
		handler->hash |= handler->rules_hash[i];
	}

	handler->messages_count = 0;

	return handler;
}


/**
 * Public API
 */
size_t mmt_single_sec_unregister( mmt_single_sec_handler_t *handler ){
	size_t i, alerts_count = 0;
	__check_null( handler, 0);

	for( i=0; i<handler->rules_count; i++ ){
		if( handler->alerts_count[ i ] == 0 )
			continue;

		if( handler->verbose ) //&& handler->rules_count > 1 )
			printf(" - rule %"PRIu32" generated %"PRIu64" verdicts\n", handler->rules_array[i]->id, handler->alerts_count[ i ] );

		alerts_count += handler->alerts_count[ i ];
	}

	//free data elements of handler
	for( i=0; i<handler->rules_count; i++ )
		rule_engine_free( handler->engines[i] );

	mmt_mem_free( handler->engines );
	mmt_mem_free( handler->rules_hash );
	mmt_mem_free( handler->alerts_count );
	mmt_mem_free( handler );


	return alerts_count;
}

size_t mmt_single_sec_get_processed_messages( const mmt_single_sec_handler_t *handler ){
	return handler->messages_count;
}
/**
 * Public API (used by mmt_sec_smp)
 */
void mmt_single_sec_process( mmt_single_sec_handler_t *handler, message_t *msg ){
#ifdef DEBUG_MODE
	mmt_assert( handler != NULL, "msg cannot be null");
	mmt_assert( msg != NULL, "msg cannot be null");
#endif

	size_t i;
	int verdict;
	const mmt_array_t *execution_trace;

	//the message does not concern to any rules handled by this #handler
	//as it does not contain any proto.att required by the handler
	if( (msg->hash & handler->hash) == 0 ){
		free_message_t( msg );
		return;
	}

	handler->messages_count ++;

	//for each rule
	for( i=0; i<handler->rules_count; i++){
		//msg does not contain any proto.att for i-th rule
		if( (msg->hash & handler->rules_hash[i]) == 0 )
			continue;

//		mmt_debug("%"PRIu64" verify rule %d", msg->counter, handler->rules_array[i]->id );

		verdict = rule_engine_process( handler->engines[i], msg );

		//found a validated/invalid trace
		if( verdict != VERDICT_UNKNOWN ){
			handler->alerts_count[i] ++;

			if( handler->callback != NULL ){
				//get execution trace
				execution_trace = rule_engine_get_valide_trace( handler->engines[i] );

				//call user-callback function
				handler->callback(
					handler->rules_array[i],
					verdict,
					msg->timestamp,
					msg->counter,
					execution_trace,
					handler->user_data_for_callback );
			}
		}
	}

	free_message_t( msg );
}
