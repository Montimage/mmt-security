/*
 * rule_verif_engine.c
 *
 *  Created on: Oct 14, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */
#include "rule_verif_engine.h"
#include "mmt_fsm.h"

typedef struct _rule_engine_struct{
	const rule_info_t *rule_info;
	//this fsm is used for execution the first events
	fsm_t *fsm_bootstrap;
	//event_id
	fsm_t **fsm_by_expecting_event_id;
	fsm_t **fsm_by_instance_id;

	size_t max_events_count, max_instances_count;

	link_node_t *events_cache;
}_rule_engine_t;

/**
 * Public API
 */
rule_engine_t* rule_engine_init( const rule_info_t *rule_info, size_t max_instances_count  ){
	_rule_engine_t *_engine = mmt_malloc( sizeof( _rule_engine_t ));
	_engine->fsm_bootstrap             = rule_info->create_instance();
	_engine->rule_info                 = rule_info;
	_engine->max_events_count          = rule_info->events_count;
	_engine->max_instances_count       = max_instances_count;
	_engine->fsm_by_expecting_event_id = mmt_malloc( rule_info->events_count * sizeof( void *) );
	_engine->fsm_by_instance_id        = mmt_malloc( max_instances_count * sizeof( void *) );
	_engine->events_cache              = NULL;
	return (rule_engine_t *) _engine;
}

/**
 * Public API
 */
void rule_engine_process( rule_engine_t *engine, const message_t *message ){
	if( engine == NULL ) return;
	_rule_engine_t *_engine = ( _rule_engine_t *) engine;
	size_t i;
	void *data          = _engine->rule_info->convert_message( message );
	const uint8_t *hash = _engine->rule_info->hash_message( data );
	uint8_t event_id;
	enum bool has_event = NO;

	mmt_debug( "===Verify Rule %d===", _engine->rule_info->id );
	//get from hash table the list of events to be verified
	for( i=0; i<_engine->max_events_count; i++ ){
		event_id = hash[i];
		if(  event_id == 0) continue;

		mmt_debug( "Event to verify: %d", event_id );
		has_event = YES;
		//verify instances that are waiting for event_id
	}
	/*
	fsm  = _handler->fsm_array[i];
	rule = _handler->rules_array[i];

	mmt_debug( "VERIFYING RULE %d", _handler->rules_array[i]->id );

	fsm_event = mmt_malloc( sizeof( fsm_event_t ));
	fsm_event->type = 1;
	//hash message to get event id;
	//rule->hash_message( message );
	fsm_event->data = rule->convert_message( message );

	//stock this event to free it laster
	_handler->events_cache[i] = insert_node_to_link_list( _handler->events_cache[i], fsm_event );

	val = fsm_handle_event( fsm, fsm_event );

	switch( val ){
	//the transition fired
	case FSM_STATE_CHANGED:
		mmt_debug( "FSM_STATE_CHANGED" );
		break;
		//the transition cannot fire
	case FSM_NO_STATE_CHANGE:
		mmt_debug( "FSM_NO_STATE_CHANGE" );
		break;
		//the rue is validated
	case FSM_FINAL_STATE_REACHED:
		_handler->callback( rule->id, 1, _handler->user_data_for_callback );
		_free_event_cache( _handler, i );
		break;
		//the rule is not validated
	case FSM_ERROR_STATE_REACHED:
		break;
	default: //avoid warning of compiler
		break;
	}

	mmt_debug( "Ret = %d", val );
	*/
	//data was not handled by any instance
	if( has_event == NO ){
		mmt_free( data );
	}else
		//_engine->events_cache = insert_node_to_link_list( _engine->events_cache, data );
		mmt_free( data );
}

static inline void _fsm_free_event_and_data( void *ev ){
	fsm_free_event( (fsm_event_t*) ev, YES );
}
/**
 * Public API
 */
void rule_engine_free( rule_engine_t *engine ){
	size_t i;
	_rule_engine_t *_engine = (_rule_engine_t *)engine;
	if( _engine == NULL ) return;

	free_link_list_and_data( _engine->events_cache, _fsm_free_event_and_data );
	fsm_free( _engine->fsm_bootstrap );

	//for( i=0; i<_engine->max_events_count )
	//	fsm
	mmt_free( _engine->fsm_by_expecting_event_id );
	mmt_free( _engine->fsm_by_instance_id );

	mmt_free( _engine );
}
