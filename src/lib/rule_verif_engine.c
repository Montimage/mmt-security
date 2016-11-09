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
	link_node_t **tmp_fsm_by_expecting_event_id;
	//instance_id - fsm_sub_instance
	link_node_t **fsm_by_instance_id;


	size_t max_events_count, max_instances_count;
	size_t total_instances_count;
	//number of instances
	size_t instances_count;

	mmt_array_t *valid_execution_trace;
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
//	mmt_assert( _engine->max_events_count >= state->transitions_count,
//			"Error: Number of outgoing transition must not be greater than number of events (%zu <= %zu)",
//			state->transitions_count, _engine->max_events_count );

	//for each outgoing transition, we add it to the list of expecting events
	for( i=0; i<state->transitions_count; i++ ){
		//i == 0: timeout => not always

		tran     = &( state->transitions[ i ] );
		event_id = tran->event_type;

		if( event_id == FSM_EVENT_TYPE_TIMEOUT )
			continue;

//d = count_nodes_from_link_list( _engine->fsm_by_expecting_event_id[ event_id ]);
//mmt_assert( d<= 300, "Stop here, total ins: %zu", _engine->total_instances_count );

//mmt_debug( "%d: event_id %d, event_type: %d, event_index: %zu, max: %zu, number of ins: %zu",
//		_engine->rule_info->id,
//		event_id, tran->event_type, i, _engine->max_events_count,
//		d);

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
	_engine->max_events_count          = rule_info->events_count + 1; //event_id start from 1
	_engine->max_instances_count       = max_instances_count;
	_engine->instances_count           = 1; //fsm_bootstrap
	//linked-list of fsm instances indexed by their expected event_id
	_engine->tmp_fsm_by_expecting_event_id = mmt_mem_alloc( _engine->max_events_count * sizeof( void *) );
	_engine->fsm_by_expecting_event_id = mmt_mem_alloc( _engine->max_events_count * sizeof( void *) );
	for( i=0; i<_engine->max_events_count; i++ )
		_engine->fsm_by_expecting_event_id[ i ] = NULL;

	//add fsm_bootstrap to the list
	_set_expecting_events_id( _engine, _engine->fsm_bootstrap );

	//linked-list of fsm instances
	_engine->fsm_by_instance_id = mmt_mem_alloc( _engine->max_instances_count * sizeof( void *) );
	for( i=0; i<_engine->max_instances_count; i++ )
		_engine->fsm_by_instance_id[ i ] = NULL;

	//add fsm_bootstrap to the first element of
	_engine->fsm_by_instance_id[ 0 ] = insert_node_to_link_list(_engine->fsm_by_instance_id[ 0 ], _engine->fsm_bootstrap );

	_engine->valid_execution_trace = NULL;

	_engine->total_instances_count = 0;
	return (rule_engine_t *) _engine;
}


/**
 * Public API
 */
void rule_engine_free( rule_engine_t *engine ){
	size_t i;
	_rule_engine_t *_engine = (_rule_engine_t *)engine;

	__check_null( engine, );

	for( i=0; i<_engine->max_events_count; i++ )
		free_link_list(_engine->fsm_by_expecting_event_id[ i ], YES );

	mmt_mem_free( _engine->fsm_by_expecting_event_id );
	mmt_mem_free( _engine->tmp_fsm_by_expecting_event_id );

	for( i=0; i<_engine->max_instances_count; i++ )
		free_link_list_and_data( _engine->fsm_by_instance_id[ i ], (void *)fsm_free );

	mmt_mem_free( _engine->fsm_by_instance_id );

	if( _engine->valid_execution_trace != NULL )
		mmt_array_free( _engine->valid_execution_trace, (void *)free_message_t );

	mmt_mem_free( _engine );
}

static inline void _store_valid_execution_trace( _rule_engine_t *_engine, fsm_t *fsm ){
	if( _engine->valid_execution_trace != NULL )
		mmt_array_free( _engine->valid_execution_trace, (void *)free_message_t );

	_engine->valid_execution_trace = mmt_array_clone( fsm_get_execution_trace( fsm ), (void *)retain_message_t );
}

/**
 * Public API
 */
const mmt_array_t* rule_engine_get_valide_trace( const rule_engine_t *engine ){
	__check_null( engine, NULL );
	_rule_engine_t *_engine = ( _rule_engine_t *)engine;
	return _engine->valid_execution_trace;
}


//Remove all instance having id = #fsm_id
static inline void _reset_engine_for_fsm( _rule_engine_t *_engine, fsm_t *fsm ){
	size_t i;
	link_node_t *node, *ptr;
	_fsm_tran_index_t *fsm_ind;
	uint16_t fsm_id = fsm_get_id( fsm );
	//remove all fsm having #fsm_id from the list #fsm_by_expecting_event_id
	for( i=0; i<_engine->max_events_count; i++ ){
		node = _engine->fsm_by_expecting_event_id[ i ];
		while( node != NULL ){
			ptr = node->next;
			fsm_ind = (_fsm_tran_index_t *) node->data;

			//found a node containing fsm having id = #fsm_id
			if( fsm_get_id( fsm_ind->fsm ) == fsm_id ){

				//head?
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
	//TODO: refine
//	_engine->total_instances_count -= count_nodes_from_link_list( _engine->fsm_by_instance_id[ fsm_id ] );
	//mmt_assert( _engine->total_instances_count >= 0, "Cannot be negative. %s:%d", __FILE__, __LINE__ );
	free_link_list_and_data( _engine->fsm_by_instance_id[ fsm_id ], (void *)fsm_free );
	//put it to be available for the other
	_engine->fsm_by_instance_id[ fsm_id ] = NULL;
}

//Remove only one instance from
// - list of expecting events
// - list of instances
static inline void _reset_engine_for_instance( _rule_engine_t *_engine, fsm_t *fsm ){
	size_t i;
	link_node_t *node, *ptr;
	_fsm_tran_index_t *fsm_ind;
	uint16_t fsm_id = fsm_get_id( fsm );
	//remove all fsm having #fsm_id from the list #fsm_by_expecting_event_id
	for( i=0; i<_engine->max_events_count; i++ ){
		node = _engine->fsm_by_expecting_event_id[ i ];
		while( node != NULL ){
			ptr = node->next;
			fsm_ind = (_fsm_tran_index_t *) node->data;

			//found a node containing fsm
			if( fsm_ind->fsm == fsm ){

				//head?
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
	//TODO: refine
//	_engine->total_instances_count -= count_nodes_from_link_list( _engine->fsm_by_instance_id[ fsm_id ] );
	_engine->fsm_by_instance_id[ fsm_id ] = remove_node_from_link_list(  _engine->fsm_by_instance_id[ fsm_id ], fsm );
	fsm_free( fsm );
}

static inline uint16_t _find_an_available_id( _rule_engine_t *_engine ){
	size_t i;
	for( i=0; i<_engine->max_instances_count; i++ )
		if( _engine->fsm_by_instance_id[ i ] == NULL ){
			return i;
		}
	//not enough
	mmt_halt( "Not enough memory %s:%d", __FILE__, __LINE__ );
	return 0;
}

enum rule_engine_result _fire_transition( _fsm_tran_index_t *fsm_ind, uint16_t event_id, message_t *message_data, void *event_data, _rule_engine_t *_engine ){
	fsm_t *fsm = fsm_ind->fsm;
	//fire a specific transition of the current state of #node->fsm
	//the transition has index = #node->tran_index
	enum fsm_handle_event_value val;
	fsm_t *new_fsm = NULL;
	uint16_t new_fsm_id = 0;

	//mmt_debug( "  transition to verify: %zu", fsm_ind->index );
	val = fsm_handle_event( fsm, fsm_ind->index, message_data, event_data, &new_fsm );

//	mmt_debug( "Verify transition: %zu of fsm %p", fsm_ind->index, fsm );

	//if the execution of the transition having index = fsm_ind->index creates a new fsm
	if( new_fsm != NULL ){
		//if a new_fsm has been created
		if( fsm == _engine->fsm_bootstrap ){
			new_fsm_id = _find_an_available_id( _engine );
			fsm_set_id( new_fsm, new_fsm_id );
		}else
			new_fsm_id = fsm_get_id( new_fsm );

		//add the new_fsm to the list of fsm(s) having the same id
		_engine->fsm_by_instance_id[ new_fsm_id  ] = insert_node_to_link_list( _engine->fsm_by_instance_id[ new_fsm_id ], new_fsm );
		_engine->total_instances_count ++;

		//TODO: refine this
//		if( _engine->total_instances_count >= 400 ){
//			rule_engine_free( _engine );
//			mmt_halt( "Too big %s:%d", __FILE__, __LINE__ );
//			mmt_debug("Number of instances: %zu, fsm_id: %d", _engine->total_instances_count, new_fsm_id );
//		}

		switch( val ){
				//the rue is validated
			case FSM_FINAL_STATE_REACHED:
				//mmt_debug( "FSM_FINAL_STATE_REACHED" );
				_store_valid_execution_trace( _engine, new_fsm );
				_reset_engine_for_fsm( _engine, new_fsm );
				return RULE_ENGINE_RESULT_VALIDATE;
				break;
				//the rule is not validated
			case FSM_ERROR_STATE_REACHED:
				_store_valid_execution_trace( _engine, new_fsm );
				_reset_engine_for_fsm( _engine, new_fsm );
				return RULE_ENGINE_RESULT_ERROR;
				break;
			case FSM_INCONCLUSIVE_STATE_REACHED:
				//mmt_debug("INCL");
				_reset_engine_for_instance( _engine, new_fsm );
				break;
//			case FSM_STATE_CHANGED:
//			case FSM_NO_STATE_CHANGE:
//			case FSM_ERR_ARG:
//				//TODO: reset
//				mmt_debug( "FSM_ERR_ARG" );
//				break;
			default:
				//add the new_fsm to lists
				//the #new_fsm does not need to listen to the transition having index = #fsm_ind->index
				_set_expecting_events_id( _engine, new_fsm );
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

			//the rue is validated
		case FSM_FINAL_STATE_REACHED:
			//mmt_debug( "FSM_FINAL_STATE_REACHED" );
			_store_valid_execution_trace( _engine, fsm );
			//remove all fsm having the same id
			_reset_engine_for_fsm( _engine, fsm );
			return RULE_ENGINE_RESULT_VALIDATE;
			break;
			//the rule is not validated
		case FSM_ERROR_STATE_REACHED:
			_store_valid_execution_trace( _engine, fsm );
			_reset_engine_for_fsm( _engine, fsm );
			return RULE_ENGINE_RESULT_ERROR;
			break;
		case FSM_INCONCLUSIVE_STATE_REACHED:
			_reset_engine_for_instance( _engine, fsm );
			break;
//		case FSM_NO_STATE_CHANGE:
//		case FSM_ERR_ARG:
//			//TODO: reset
//			mmt_debug( "FSM_ERR_ARG" );
//			break;
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
	__check_null( engine,  RULE_ENGINE_RESULT_UNKNOWN );
	__check_null( message, RULE_ENGINE_RESULT_UNKNOWN );

	_rule_engine_t *_engine = ( _rule_engine_t *) engine;
	size_t i;
	void *data           = _engine->rule_info->convert_message( message );
	const uint16_t *hash = _engine->rule_info->hash_message( data );
	uint8_t event_id;
	link_node_t *node;
	_fsm_tran_index_t *fsm_ind;
	enum rule_engine_result ret = RULE_ENGINE_RESULT_UNKNOWN;;
	//insert #message pointer to head of #data;

	for( i=0; i<_engine->max_events_count; i++ )
		_engine->tmp_fsm_by_expecting_event_id[ i ] = _engine->fsm_by_expecting_event_id[ i ];

	//	mmt_debug( "Verify message counter: %"PRIu64", ts: %"PRIu64, message->counter, message->timestamp );
	//mmt_debug( "===Verify Rule %d=== %zu", _engine->rule_info->id, _engine->max_events_count );
	//get from hash table the list of events to be verified
	//event_id start from 1, but hash starts from 0
	for( i=0; i<_engine->max_events_count - 1; i++ ){
		event_id = hash[i];
		//this event does not fire
		if(  event_id == 0 ) continue;
		//mmt_debug( "Event_id : %d", event_id );

		//verify instances that are waiting for event_id
		node = _engine->tmp_fsm_by_expecting_event_id[ event_id ];

		//for each instance
		while( node != NULL ){

			fsm_ind = (_fsm_tran_index_t *)node->data;
			node = node->next;
			//put this after node = node->next
			// because #node can be freed( or inserted a new node) in the function #_fire_transition

			ret = _fire_transition( fsm_ind, event_id, message, data, _engine );

			//get only one verdict per packet
			if( ret != RULE_ENGINE_RESULT_UNKNOWN ){
				//must free #data before returning
				mmt_mem_free( data );
				return ret;
			}
		}
	}

	mmt_mem_free( data );
	//data was not handled by any instance
	return RULE_ENGINE_RESULT_UNKNOWN;
}


