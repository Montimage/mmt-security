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

	mmt_map_t *valid_execution_trace;
	fsm_t *valid_fsm;
}_rule_engine_t;

/**
 * In the next event,
 * the #fsm will fire the #index-th transition of its current state
 */
typedef struct _fsm_tran_index_struct{
	size_t index;
	fsm_t *fsm;
}_fsm_tran_index_t ;

static inline _fsm_tran_index_t* _create_fsm_tran_index_t( size_t index, fsm_t *fsm){
	_fsm_tran_index_t *ret = mmt_mem_alloc( sizeof( _fsm_tran_index_t));
	ret->index = index;
	ret->fsm   = fsm;
	return ret;
}

/**
 * Index the transitions of #fsm that can be fired in the next event.
 */
static inline void _set_expecting_events_id( _rule_engine_t *_engine, fsm_t *fsm ){
	size_t i;
	uint16_t event_id;
	const fsm_transition_t *tran;
	const fsm_state_t *state = fsm_get_current_state( fsm );

	//from a state: 2 outgoing transitions have 2 different events
	mmt_assert( _engine->max_events_count >= state->transitions_count,
			"Error: Number of outgoing transition must not be greater than number of events (%zu <= %zu)",
			state->transitions_count, _engine->max_events_count );

	//for each outgoing transition, we add it to the list of expecting events
	for( i=0; i<state->transitions_count; i++ ){
		//i == 0: timeout => not always

		tran     = &( state->transitions[ i ] );
		event_id = tran->event_type;

		//TODO: check if a rule has not continue event_id ranges
		//e.g., a rule having 2 event ids: 1 and 7, so, 1 % 2 == 7 % 2
		//MUST: event_id < _engine->max_events_count
		event_id = event_id % _engine->max_events_count;

//mmt_debug( "%d: event_id %d, event_type: %d, event_index: %zu, max: %zu",
//		_engine->rule_info->id,
//		event_id, tran->event_type, i, _engine->max_events_count );

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
	_rule_engine_t *_engine = mmt_mem_alloc( sizeof( _rule_engine_t ));
	_engine->fsm_bootstrap             = rule_info->create_instance();
	fsm_set_id( _engine->fsm_bootstrap, 0 );

	_engine->rule_info                 = rule_info;
	_engine->max_events_count          = rule_info->events_count + 1; //1 for timeout;
	_engine->max_instances_count       = max_instances_count;
	_engine->instances_count           = 1; //fsm_bootstrap
	//linked-list of fsm instances indexed by their expected event_id
	_engine->fsm_by_expecting_event_id = mmt_mem_alloc( _engine->max_events_count * sizeof( void *) );
	for( i=0; i<_engine->max_events_count; i++ )
		_engine->fsm_by_expecting_event_id[ i ] = NULL;

	//add fsm_bootstrap to the list
	_set_expecting_events_id( _engine, _engine->fsm_bootstrap );

	//linked-list of fsm instances
	_engine->fsm_by_instance_id = mmt_mem_alloc( _engine->max_instances_count * sizeof( void *) );
	for( i=0; i<_engine->max_instances_count; i++ )
		_engine->fsm_by_instance_id[ i ] = NULL;

	//cache _msg_t_ and message_t
	_engine->events_data_cache = mmt_map_init( compare_pointer );

	_engine->valid_execution_trace = NULL;
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
	mmt_map_iterate( _engine->events_data_cache, (void *)mmt_mem_free, NULL );
	mmt_map_free( _engine->events_data_cache, NO );

	//free the bootstap fsm
	fsm_free( _engine->fsm_bootstrap );

	for( i=0; i<_engine->max_events_count; i++ )
		free_link_list(_engine->fsm_by_expecting_event_id[ i ], YES );

	mmt_mem_free( _engine->fsm_by_expecting_event_id );

	for( i=0; i<_engine->max_instances_count; i++ )
		free_link_list_and_data( _engine->fsm_by_instance_id[ i ], (void *)fsm_free );

	mmt_mem_free( _engine->fsm_by_instance_id );

	mmt_map_free_key_and_data( _engine->valid_execution_trace, NULL, (void *)free_message_t );
	mmt_mem_free( _engine );
}

/**
 * Public API
 */
const mmt_map_t* rule_engine_get_valide_trace( const rule_engine_t *engine ){
	_rule_engine_t *_engine = ( _rule_engine_t *)engine;
	return _engine->valid_execution_trace;
}


static inline void _iterate_to_retain_data( void *key, void *data, void *user_data, size_t index, size_t total ){
	(void *)retain_message_t( (message_t *) data );
}

/**
 * Store the current execution trace of #fsm to #_engine->valid_execution_trace
 */
void _store_valide_trace( _rule_engine_t *_engine, const fsm_t *fsm ){
	//free the old trace
	//TODO: free data also?
	mmt_map_free_key_and_data( _engine->valid_execution_trace, NULL, (void *)free_message_t );

	//create a new map storing the execution trace of #fsm
	_engine->valid_execution_trace = fsm_get_execution_trace( _engine->valid_fsm );
	mmt_map_iterate( _engine->valid_execution_trace, _iterate_to_retain_data, NULL );
}

static inline void _reset_engine_for_fsm( _rule_engine_t *_engine, uint16_t fsm_id ){
	size_t i;
	link_node_t *node, *ptr;
	_fsm_tran_index_t *fsm_ind;
	//remove all fsm having #fsm_id from the list #fsm_by_expecting_event_id
	for( i=0; i<_engine->max_events_count; i++ ){
		node = _engine->fsm_by_expecting_event_id[ i ];
		while( node != NULL ){
			ptr = node->next;
			fsm_ind = (_fsm_tran_index_t *) node->data;

			//found a node containing fsm having id = #fsm_id
			if( fsm_get_id( fsm_ind->fsm ) == fsm_id ){

				//head
				if( node == _engine->fsm_by_expecting_event_id[ i ] ){
					if( ptr != NULL ) ptr->prev = NULL;
					_engine->fsm_by_expecting_event_id[ i ] = ptr;
				}else{
					node->prev->next = ptr;
					if( ptr != NULL )
						ptr->prev = node->prev;
				}
				mmt_mem_free( fsm_ind );//node->data
				mmt_mem_free( node );
			}
			node = ptr;
		}
	}

	//remove all fsm having id == #fsm_id and free them
	free_link_list_and_data( _engine->fsm_by_instance_id[ fsm_id ], (void *)fsm_free );
	//put it to be available for the other
	_engine->fsm_by_instance_id[ fsm_id ] = NULL;
}

static inline uint16_t _find_an_available_id( _rule_engine_t *_engine ){
	size_t i;
	for( i=0; i<_engine->max_instances_count; i++ )
		if( _engine->fsm_by_instance_id[ i ] == NULL )
			return i;
	//not enough
	return 0;
}

enum rule_engine_result _fire_transition( _fsm_tran_index_t *fsm_ind, uint16_t event_id, message_t *message_data, void *event_data, _rule_engine_t *_engine ){
	fsm_t *fsm = fsm_ind->fsm;
	//fire a specific transition of the current state of #node->fsm
	//the transition has index = #node->tran_index
	enum fsm_handle_event_value val;
	mmt_map_t *trace_map;
	fsm_t *new_fsm = NULL;
	uint16_t new_fsm_id = 0;

	//mmt_debug( "  transition to verify: %zu", fsm_ind->index );
	val = fsm_handle_event( fsm, fsm_ind->index, message_data, event_data, &new_fsm );

	//if the execution of the transition having index = fsm_ind->index creates a new fsm
	if( new_fsm != NULL ){
		//if the new_fsm has been created
		if( fsm == _engine->fsm_bootstrap ){
			new_fsm_id = _find_an_available_id( _engine );
			fsm_set_id( new_fsm, new_fsm_id );
		}else
			new_fsm_id = fsm_get_id( new_fsm );

		//add the new_fsm to lists
		_set_expecting_events_id( _engine, new_fsm );
		//add the new_fsm to the list of fsm(s) having the same id
		_engine->fsm_by_instance_id[ new_fsm_id  ] = insert_node_to_link_list( _engine->fsm_by_instance_id[ new_fsm_id ], new_fsm );


		switch( val ){
			case FSM_STATE_CHANGED:
				return RULE_ENGINE_RESULT_UNKNOWN;
				break;

				//the transition cannot fire
			case FSM_NO_STATE_CHANGE:
				//mmt_debug( "FSM_NO_STATE_CHANGE" );
				return RULE_ENGINE_RESULT_UNKNOWN;
				break;

				//the rue is validated
			case FSM_FINAL_STATE_REACHED:
				//mmt_debug( "FSM_FINAL_STATE_REACHED" );
				_engine->valid_fsm = new_fsm;
				return RULE_ENGINE_RESULT_VALIDATE;
				break;
				//the rule is not validated
			case FSM_ERROR_STATE_REACHED:
				_engine->valid_fsm = new_fsm;
				return RULE_ENGINE_RESULT_ERROR;
				break;
			case FSM_ERR_ARG:
				//TODO: reset
				mmt_debug( "FSM_ERR_ARG" );
				break;
			default:
				break;
			}
	}
	else{
		switch( val ){
		case FSM_STATE_CHANGED:
			//mmt_debug( "FSM_STATE_CHANGED" );

			//remove from old list
			_engine->fsm_by_expecting_event_id[ event_id ] =
					remove_node_from_link_list( _engine->fsm_by_expecting_event_id[ event_id ], (void *)fsm_ind );
			mmt_mem_free( fsm_ind );
			//then add to new list(s)
			_set_expecting_events_id( _engine, fsm );

			return RULE_ENGINE_RESULT_UNKNOWN;
			break;

			//the transition cannot fire
		case FSM_NO_STATE_CHANGE:
			//mmt_debug( "FSM_NO_STATE_CHANGE" );
			return RULE_ENGINE_RESULT_UNKNOWN;
			break;

			//the rue is validated
		case FSM_FINAL_STATE_REACHED:
			//mmt_debug( "FSM_FINAL_STATE_REACHED" );
			_engine->valid_fsm = fsm;
			return RULE_ENGINE_RESULT_VALIDATE;
			break;
			//the rule is not validated
		case FSM_ERROR_STATE_REACHED:
			_engine->valid_fsm = fsm;
			return RULE_ENGINE_RESULT_ERROR;
			break;
		case FSM_ERR_ARG:
			//TODO: reset
			mmt_debug( "FSM_ERR_ARG" );
			break;
		default:
			break;
		}
	}
	return RULE_ENGINE_RESULT_UNKNOWN;
}

/**
 * Public API
 */
enum rule_engine_result rule_engine_process( rule_engine_t *engine, message_t *message ){
	//mmt_assert( engine != NULL, "Error: Engine cannot be NULL" );

	_rule_engine_t *_engine = ( _rule_engine_t *) engine;
	size_t i;
	void *data           = _engine->rule_info->convert_message( message );
	const uint16_t *hash = _engine->rule_info->hash_message( data );
	uint8_t event_id;
	link_node_t *node;
	_fsm_tran_index_t *fsm_ind;
	enum rule_engine_result ret = RULE_ENGINE_RESULT_UNKNOWN;;
	//insert #message pointer to head of #data;

	//mmt_debug( "===Verify Rule %d=== %zu", _engine->rule_info->id, _engine->max_events_count );
	//get from hash table the list of events to be verified
	for( i=0; i<_engine->max_events_count; i++ ){
		event_id = hash[i];
		//this event does not fire
		if(  event_id == 0 ) continue;

		event_id = event_id % _engine->max_events_count;

		//verify instances that are waiting for event_id
		node = _engine->fsm_by_expecting_event_id[ event_id ];

		//for each instance
		while( node != NULL ){

			fsm_ind = (_fsm_tran_index_t *)node->data;
			node = node->next;
			//put this after node = node->next
			// because #node can be freed in the function #_fire_transition

			ret = _fire_transition( fsm_ind, event_id, message, data, _engine );

			if( ret != RULE_ENGINE_RESULT_UNKNOWN){
				if( ret == RULE_ENGINE_RESULT_VALIDATE || ret == RULE_ENGINE_RESULT_ERROR ){
					//store execution trace
					_store_valide_trace( _engine, _engine->valid_fsm );
					//remove all fsm having the same id
					_reset_engine_for_fsm( _engine, fsm_get_id( _engine->valid_fsm ) );

					//Must return here
					return ret;
				}
			}
		}
	}

	//data was not handled by any instance
	return RULE_ENGINE_RESULT_UNKNOWN;
}


