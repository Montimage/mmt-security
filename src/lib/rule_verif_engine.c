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
	//event_id - fsm_instance
	link_node_t **fsm_by_expecting_event_id;
	//instance_id - fsm_sub_instance
	link_node_t **fsm_by_instance_id;

	size_t max_events_count, max_instances_count;
	//number of instances
	size_t instances_count;
	//cache of data using by (fsm) events
	mmt_map_t *events_data_cache;

	fsm_t *valid_fsm;

	//for passing parameter of map_iterate
	void *user_data;
}_rule_engine_t;


typedef struct _fsm_index_struct{
	size_t index;
	fsm_t *fsm;
}_fsm_tran_index_t ;

static inline _fsm_tran_index_t* _create_fsm_tran_index_t( size_t index, fsm_t *fsm){
	_fsm_tran_index_t *ret = mmt_malloc( sizeof( _fsm_tran_index_t));
	ret->index = index;
	ret->fsm   = fsm;
	return ret;
}

static inline void _set_expecting_events_id( _rule_engine_t *_engine, fsm_t *fsm ){
	size_t i;
	uint16_t event_id;
	fsm_transition_t *tran;
	const fsm_state_t *state = fsm_get_current_state( fsm );

	mmt_assert( _engine->max_events_count >= state->transitions_count,
			"Error: Number of outgoing transition must not be greater than number of events (%zu <= %zu)",
			state->transitions_count, _engine->max_events_count );

	//for each outgoing transition, we add it to the list of expecting events
	for( i=0; i<state->transitions_count; i++ ){
		tran     = &( state->transitions[ i ] );
		event_id = tran->event_type;

		event_id = event_id % _engine->max_events_count;

		//if event having #event_id occurs,
		// then #fsm will fire the i-th transition from its current state
		_engine->fsm_by_expecting_event_id[ event_id ] =
				insert_node_to_link_list( _engine->fsm_by_expecting_event_id[ event_id],
													_create_fsm_tran_index_t( i, fsm ) );
	}
}

/**
 * Public API
 */
rule_engine_t* rule_engine_init( const rule_info_t *rule_info, size_t max_instances_count  ){
	size_t i;
	_rule_engine_t *_engine = mmt_malloc( sizeof( _rule_engine_t ));
	_engine->fsm_bootstrap             = rule_info->create_instance();
	fsm_set_id( _engine->fsm_bootstrap, 0 );

	_engine->rule_info                 = rule_info;
	_engine->max_events_count          = rule_info->events_count + 1; //1 for timeout;
	_engine->max_instances_count       = max_instances_count;
	_engine->instances_count           = 1; //fsm_bootstrap
	//linked-list of fsm instances indexed by their expected event_id
	_engine->fsm_by_expecting_event_id = mmt_malloc( _engine->max_events_count * sizeof( void *) );
	for( i=0; i<_engine->max_events_count; i++ )
		_engine->fsm_by_expecting_event_id[ i ] = NULL;

	//add fsm_bootstrap to the list
	_set_expecting_events_id( _engine, _engine->fsm_bootstrap );

	//linked-list of fsm instances
	_engine->fsm_by_instance_id = mmt_malloc( _engine->max_instances_count * sizeof( void *) );
	for( i=0; i<_engine->max_instances_count; i++ )
		_engine->fsm_by_instance_id[ i ] = NULL;

	_engine->events_data_cache = mmt_map_init( compare_pointer );

	_engine->valid_fsm = NULL;
	return (rule_engine_t *) _engine;
}


/**
 * Public API
 */
void rule_engine_free( rule_engine_t *engine ){
	size_t i;
	_rule_engine_t *_engine = (_rule_engine_t *)engine;
	if( _engine == NULL ) return;

	//free key of the map
	mmt_map_iterate( _engine->events_data_cache, (void *)mmt_free, NULL );
	mmt_map_free( _engine->events_data_cache, NO );

	fsm_free( _engine->fsm_bootstrap );

	for( i=0; i<_engine->max_events_count; i++ )
		free_link_list(_engine->fsm_by_expecting_event_id[ i ], YES );

	for( i=0; i<_engine->max_instances_count; i++ )
		free_link_list_and_data( _engine->fsm_by_instance_id[ i ], (void *)fsm_free );

	mmt_free( _engine->fsm_by_expecting_event_id );
	mmt_free( _engine->fsm_by_instance_id );

	mmt_free( _engine );
}


static void _iterate_to_update_event( void *key, void *data, void *u_data, size_t index, size_t total){
	_rule_engine_t *_engine = ( _rule_engine_t *)u_data;
	message_t *msg =  mmt_map_get_data( _engine->events_data_cache, data );
	if( msg == NULL )
		return;
	mmt_map_set_data( (mmt_map_t *)_engine->user_data, key, (void *)msg, YES );
}

mmt_map_t* get_execution_trace( _rule_engine_t *_engine ){
	mmt_map_t *map = fsm_get_execution_trace( _engine->valid_fsm );
	mmt_map_t *new_map = mmt_map_init( compare_uint16_t );
	_engine->user_data = new_map;
	mmt_map_iterate( map, _iterate_to_update_event, _engine );
	return new_map;
}


static void _print_message_t( void *key, void *data, void *u_data, size_t index, size_t total){
	size_t i;
	mmt_assert( data != NULL, "Error: data cannot be null, %s:%d", __FILE__, __LINE__ );
	message_t *msg = (message_t *) data;
	uint16_t id    = *(uint16_t *) key;
	mmt_debug( "- message %d, counter = %"PRIu32", timer = %"PRIu64, id, msg->counter, msg->timestamp );
	for( i=0; i<msg->elements_count; i++)
		if( msg->elements[i] != NULL ){
			mmt_debug( "   %d_%d", msg->elements[i]->proto_id, msg->elements[i]->att_id );
		}else
			mmt_debug( "   NULL");
}

enum rule_engine_result _fire_transition( _fsm_tran_index_t *fsm_ind, uint16_t event_id, void *event_data, _rule_engine_t *_engine ){
	fsm_t *fsm = fsm_ind->fsm;
	//fire a specific transition of the current state of #node->fsm
	//the transition has index = #node->tran_index
	enum fsm_handle_event_value val;
	mmt_map_t *trace_map;

	val = fsm_handle_event( fsm, fsm_ind->index, event_data );
	mmt_debug( "  transition to verify: %zu", fsm_ind->index );

	switch( val ){
	case FSM_STATE_CHANGED:
		mmt_debug( "FSM_STATE_CHANGED" );

		//remove from old list
		_engine->fsm_by_expecting_event_id[ event_id ] =
					remove_node_from_link_list( _engine->fsm_by_expecting_event_id[ event_id ], (void *)fsm_ind );
		mmt_free( fsm_ind );
		//then add to new list(s)
		_set_expecting_events_id( _engine, fsm );

		break;

		//the transition cannot fire
	case FSM_NO_STATE_CHANGE:
		mmt_debug( "FSM_NO_STATE_CHANGE" );
		break;

		//the rue is validated
	case FSM_FINAL_STATE_REACHED:
		mmt_debug( "FSM_FINAL_STATE_REACHED" );
		_engine->valid_fsm = fsm;
		trace_map = get_execution_trace( _engine );
		mmt_map_iterate( trace_map, _print_message_t, NULL );
		mmt_map_free( trace_map, NO );

		return RULE_ENGINE_RESULT_VALIDATE;
		break;
		//the rule is not validated
	case FSM_ERROR_STATE_REACHED:
		mmt_debug( "FSM_ERROR_STATE_REACHED" );

		return RULE_ENGINE_RESULT_ERROR;
		break;
	case FSM_ERR_ARG:
		mmt_debug( "FSM_ERR_ARG" );
		break;
	default:
		break;
	}

	return RULE_ENGINE_RESULT_UNKNOWN;
}

/**
 * Public API
 */
enum rule_engine_result rule_engine_process( rule_engine_t *engine, const message_t *message ){
	mmt_assert( engine != NULL, "Error: Engine cannot be NULL" );

	_rule_engine_t *_engine = ( _rule_engine_t *) engine;
	size_t i;
	void *data          = _engine->rule_info->convert_message( message );
	const uint8_t *hash = _engine->rule_info->hash_message( data );
	uint8_t event_id;
	enum bool has_event = NO;
	link_node_t *node;
	_fsm_tran_index_t *fsm_ind;
	//insert #message pointer to head of #data;

	mmt_debug( "===Verify Rule %d===", _engine->rule_info->id );
	//get from hash table the list of events to be verified
	for( i=0; i<_engine->max_events_count; i++ ){
		event_id = hash[i];
		//this event does not fire
		if(  event_id == 0) continue;

		mmt_debug( "Event to verify: %d", event_id );
		event_id = event_id % _engine->max_events_count;

		//verify instances that are waiting for event_id
		node = _engine->fsm_by_expecting_event_id[ event_id ];
		//for each instance
		while( node != NULL ){
			fsm_ind = (_fsm_tran_index_t *)node->data;
			node = node->next;
			//put this after node = node->next
			// because #node can be freed in the function #_fire_transition
			_fire_transition( fsm_ind, event_id, data, _engine );
		}

		has_event = YES;
	}

	//data was not handled by any instance
	if( has_event == NO ){
		mmt_free( data );
	}else
		mmt_map_set_data( _engine->events_data_cache, data, (void *)message, YES );

	return RULE_ENGINE_RESULT_UNKNOWN;
}


