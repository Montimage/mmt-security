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
	const rule_info_t ** rules_array;
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
}__aligned;


/**
 * Public API
 */
mmt_single_sec_handler_t *mmt_single_sec_register( const rule_info_t *const*rules_array, size_t rules_count, bool verbose,
		mmt_sec_callback callback, void *user_data){
	int i, j, index;
	const rule_engine_t *engine;
	const rule_info_t *rule;
	const proto_attribute_t *p;
	uint32_t max_instance_count = mmt_sec_get_config( MMT_SEC__CONFIG__SECURITY__MAX_INSTANCES );
	__check_null( rules_array, NULL );

	mmt_single_sec_handler_t *handler = mmt_mem_alloc( sizeof( mmt_single_sec_handler_t ));
	handler->rules_count = rules_count;
	handler->rules_array = mmt_mem_alloc( sizeof (void * ) * rules_count );;
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

		handler->rules_array[i]  = rule;
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
			printf(" - rule %"PRIu32" generated %zu verdicts\n", handler->rules_array[i]->id, handler->alerts_count[ i ] );

		alerts_count += handler->alerts_count[ i ];
	}

	//free data elements of handler
	for( i=0; i<handler->rules_count; i++ )
		rule_engine_free( handler->engines[i] );

	mmt_mem_free( handler->rules_array );
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
	if( unlikely((msg->hash & handler->hash) == 0 )){
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

			//get execution trace
			execution_trace = rule_engine_get_valide_trace( handler->engines[i] );

			//callback fucntion of rule
			if( handler->rules_array[i]->if_satisfied != NULL )
				handler->rules_array[i]->if_satisfied(
						handler->rules_array[i],
						verdict,
						msg->timestamp,
						msg->counter,
						execution_trace );

			//call user-callback function
			if( handler->callback != NULL ){
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


#ifdef ADD_OR_RM_RULES_RUNTIME
static inline void _swap_rule( mmt_single_sec_handler_t *handler, int i, int j ){
	const rule_info_t *rule;
	rule_engine_t *engine;

	size_t tmp;
	uint64_t hash;

	if( i==j )
		return;

	//swap rule info
	rule = handler->rules_array[ i ];
	handler->rules_array[ i ] = handler->rules_array[ j ];
	handler->rules_array[ j ] = rule;

	//swap rule engine
	engine = handler->engines[ i ];
	handler->engines[ i ] = handler->engines[ j ];
	handler->engines[ j ] = engine;

	//swap alert count
	tmp = handler->alerts_count[ i ];
	handler->alerts_count[ i ] = handler->alerts_count[ j ];
	handler->alerts_count[ j ] = tmp;

	//swap rule hash
	hash = handler->rules_hash[ i ];
	handler->rules_hash[ i ] = handler->rules_hash[ j ];
	handler->rules_hash[ j ] = hash;
}

/**
 *
 * @param handler
 * @param i
 */
static inline void _free_rule( mmt_single_sec_handler_t *handler, size_t i ){
	rule_engine_free( handler->engines[i] );
	handler->engines[i] = NULL;
}

//PUBLIC_API
size_t mmt_single_sec_remove_rules( mmt_single_sec_handler_t *handler, size_t rules_count, const uint32_t* rules_id_set ){
	size_t i, j;
	size_t removed_rules_count = 0;
	const rule_info_t *rule;

	for( i=0; i<handler->rules_count; i++ ){
		rule = handler->rules_array[i];
		j = index_of( rule->id, rules_id_set, rules_count );

		//NOT FOUND
		if( j == rules_count )
			continue;

		//move the rule to be remove to the end
		_swap_rule( handler, i, handler->rules_count - 1 );

		//remove the rule that is now at the end
		_free_rule( handler, handler->rules_count - 1 );

		//reduce number of rules
		handler->rules_count --;

		removed_rules_count ++;
	}

	//update global hash if need
	if( removed_rules_count > 0 ){
		handler->hash = 0;
		for( i=0; i<handler->rules_count; i++ )
			handler->hash |= handler->rules_hash[i];
	}

	return removed_rules_count;
}

//PUBLIC_API
size_t mmt_single_sec_add_rules( mmt_single_sec_handler_t *handler, size_t new_rules_count,
		const rule_info_t *const* new_rules_arr, bool update_if_existing ){
	bool *checked_rules = mmt_mem_alloc( sizeof( bool ) * new_rules_count );
	size_t i, j, k;
	size_t add_rules_count = 0, replace_rules_count = 0;
	size_t max_instances_count = mmt_sec_get_config( MMT_SEC__CONFIG__SECURITY__MAX_INSTANCES );

	const rule_info_t **old_rules_array;
	rule_engine_t **old_engines;
	size_t *old_alerts_count;
	uint64_t *old_rules_hash;

	//no new rules being checked
	for( i=0; i<new_rules_count; i++ )
		checked_rules[ i ] = NO;

	//when replace
	if( update_if_existing ){
		for( i=0; i<handler->rules_count; i++ )
			for( j=0; j<new_rules_count; j++ ){
				if( handler->rules_array[i]->id == new_rules_arr[j]->id ){
					//update rule info
					handler->rules_array[i] = new_rules_arr[j];

					//free old engine
					rule_engine_free( handler->engines[i] );
					//update new engine
					handler->engines[i] = rule_engine_init( handler->rules_array[i], max_instances_count);

					//update hash number of this rule
					handler->rules_hash[i]   = 0;
					for( k=0; k<handler->engines[i]->events_count; k++ )
						handler->rules_hash[i] |= handler->engines[i]->events_hash[ k ];

					//mark the new j-th rule being processed
					checked_rules[ j ] = YES;

					replace_rules_count ++;

					//goto the next rule
					break;
				}
			}
	}

	add_rules_count = new_rules_count - replace_rules_count;
	//There are still other new rules to be add
	if( add_rules_count > 0 ){
		//old_rules_array
		old_rules_array  = handler->rules_array;
		old_engines      = handler->engines;
		old_alerts_count = handler->alerts_count;
		old_rules_hash   = handler->rules_hash;

		//extends the current arrays by create a new one
		handler->rules_array  = mmt_mem_alloc( sizeof( void *)    * ( handler->rules_count + add_rules_count ));
		handler->engines      = mmt_mem_alloc( sizeof( void *)    * ( handler->rules_count + add_rules_count ));
		handler->alerts_count = mmt_mem_alloc( sizeof( size_t )   * ( handler->rules_count + add_rules_count ));
		handler->rules_hash   = mmt_mem_alloc( sizeof( uint64_t ) * ( handler->rules_count + add_rules_count ));

		//retake the old values
		for( i=0; i<handler->rules_count; i++ ){
			handler->rules_array[ i ]  = old_rules_array[ i ];
			handler->engines[ i ]      = old_engines[ i ];
			handler->alerts_count[ i ] = old_alerts_count[ i ];
			handler->rules_hash[ i ]   = old_rules_hash[ i ];
		}

		//free the old memories
		mmt_mem_free( old_rules_array  );
		mmt_mem_free( old_engines      );
		mmt_mem_free( old_alerts_count );
		mmt_mem_free( old_rules_hash   );

		//add the new rules
		j = 0;
		for( i=handler->rules_count; i< (handler->rules_count + add_rules_count); i++ ){

			//find the fist rule that is not processed
			while( checked_rules[ j ] == YES  && j < new_rules_count )
				j ++;

			//all rules being processed
			mmt_assert( j < new_rules_count, "Impossible %zu %zu", i, j);

			//mark the new j-th rule being processed
			checked_rules[ j ] = YES;

			//init variables for this rule
			handler->rules_array[ i ]  = new_rules_arr[ j ];
			handler->engines[ i ]      = rule_engine_init( handler->rules_array[ i ], max_instances_count );
			handler->alerts_count[ i ] = 0;
			handler->rules_hash[ i ]   = 0;
			//hash number for this rule
			for( k=0; k<handler->engines[i]->events_count; k++ )
				handler->rules_hash[i] |= handler->engines[i]->events_hash[ k ];
		}

		//new rules size
		handler->rules_count += add_rules_count;
	}

	//free temporary memory
	mmt_mem_free( checked_rules );

	//update global hash if need
	handler->hash = 0;
	for( i=0; i<handler->rules_count; i++ )
		handler->hash |= handler->rules_hash[i];

	return add_rules_count;
}
#endif
