/*
 * rule_verif_engine.c
 *
 *  Created on: Oct 14, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */
#include "rule_verif_engine.h"

/**
 * In the next event,
 * the #fsm will fire the #index-th transition of its current state
 */
typedef struct _fsm_tran_index_struct{
	uint64_t counter;     //index of the last verified message
	size_t index;         //index of the transition of the current state of #fsm to be verified
	fsm_t *fsm;           //fsm to be verified
}_fsm_tran_index_t ;

static inline _fsm_tran_index_t* _create_fsm_tran_index_t( rule_engine_t *_engine, size_t index, fsm_t *fsm, uint64_t counter){

	_fsm_tran_index_t *ret = mmt_mem_alloc( sizeof( _fsm_tran_index_t));
	ret->index   = index;
	ret->fsm     = fsm;
	ret->counter = counter;
	return ret;
}

/**
 * Index the transitions of #fsm that can be fired in the next event.
 */
static inline void _set_expecting_events_id( rule_engine_t *_engine, fsm_t *fsm, bool is_add_timeout, uint64_t counter ){
	size_t i;
	uint16_t event_id;
	const fsm_transition_t *tran;
	const fsm_state_t *state = fsm_get_current_state( fsm );
	_fsm_tran_index_t *fsm_ind;

	//from a state: 2 outgoing transitions have 2 different events
#ifdef DEBUG_MODE
	mmt_assert( _engine->max_events_size >= state->transitions_count,
			"Error: Number of outgoing transition must not be greater than number of events (%zu <= %zu)",
			state->transitions_count, _engine->max_events_size );
#endif

	//for each outgoing transition, we add it to the list of expecting events
	for( i=0; i<state->transitions_count; i++ ){
		//i == 0: timeout => not always

		tran     = &( state->transitions[ i ] );
		event_id = tran->event_type;

		if( event_id == FSM_EVENT_TYPE_TIMEOUT && !is_add_timeout )
			continue;

//d = count_nodes_from_link_list( _engine->fsm_by_expecting_event_id[ event_id ]);
//mmt_assert( d<= 300, "Stop here, total ins: %zu", _engine->total_instances_count );

//mmt_debug( "%d: event_id %d, event_type: %d, event_index: %zu, max: %zu, number of ins: %zu",
//		_engine->rule_info->id,
//		event_id, tran->event_type, i, _engine->max_events_count,
//		d);

		//if event having #event_id occurs,
		// then #fsm will fire the i-th transition from its current state
		fsm_ind = _create_fsm_tran_index_t( _engine, i, fsm, counter );

		_engine->fsm_by_expecting_event_id[ event_id ] =
				insert_node_to_link_list( _engine->fsm_by_expecting_event_id[ event_id], fsm_ind );
	}
}

static inline enum verdict_type _get_verdict( int rule_type, enum fsm_handle_event_value result ){
	switch ( rule_type ) {
	case RULE_TYPE_TEST:
	case RULE_TYPE_SECURITY:
		switch( result ){
		case FSM_ERROR_STATE_REACHED:
			return VERDICT_NOT_RESPECTED;
		case FSM_FINAL_STATE_REACHED:
			return VERDICT_RESPECTED;
		default:
			return VERDICT_UNKNOWN;
		}
		break;
	case RULE_TYPE_ATTACK:
	case RULE_TYPE_EVASION:
		switch( result ){
		case FSM_ERROR_STATE_REACHED:
			return VERDICT_UNKNOWN; //VERDICT_NOT_DETECTED;
		case FSM_FINAL_STATE_REACHED:
			return VERDICT_DETECTED;
		default:
			return VERDICT_UNKNOWN;
		}
		break;
	default:
		mmt_halt("Error 22: Property type should be a security rule or an attack.\n");
	}//end of switch
	return VERDICT_UNKNOWN;
}




static inline void _store_valid_execution_trace( rule_engine_t *_engine, fsm_t *fsm ){
	size_t i;
	const mmt_array_t *array = fsm_get_execution_trace( fsm );

#ifdef DEBUG_MODE
	mmt_assert( array->elements_count == _engine->max_events_size, "Impossible" );
#endif

	for( i=0; i<_engine->max_events_size; i++ ){
		//free old message
		free_message_t( _engine->valid_execution_trace->data[i] );

		//increase number of references to each message
		_engine->valid_execution_trace->data[i] = mmt_mem_atomic_retain( array->data[i] );
	}
}

/**
 * Public API
 */
const mmt_array_t* rule_engine_get_valide_trace( const rule_engine_t *engine ){
#ifdef DEBUG_MODE
	mmt_assert( engine != NULL, "engine cannot be null" );
#endif

	rule_engine_t *_engine = ( rule_engine_t *)engine;
	return _engine->valid_execution_trace;
}


/**
 * Remove all instances (fsm) having same id with #fsm
 */
static inline void _reset_engine_for_fsm( rule_engine_t *_engine, fsm_t *fsm ){
	size_t i;
	link_node_t *node, *ptr;
	_fsm_tran_index_t *fsm_ind;
	uint16_t fsm_id = fsm_get_id( fsm );
	//remove all fsm having #fsm_id from the list #fsm_by_expecting_event_id
	for( i=0; i<_engine->max_events_size; i++ ){
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
				mmt_mem_force_free( fsm_ind );//node->data

				mmt_mem_force_free( node );
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
/**
 * Remove only one instance from
 * - (1) list of expecting events, and from
 * - (2) list of instances
 */
static inline void _reset_engine_for_instance( rule_engine_t *_engine, fsm_t *fsm ){
	size_t i;
	link_node_t *node, *ptr;
	_fsm_tran_index_t *fsm_ind;
	uint16_t fsm_id = fsm_get_id( fsm );

	//(1) - remove fsm from the list #fsm_by_expecting_event_id

	//for each entry (that is a list) of expecting event i
	for( i=0; i<_engine->max_events_size; i++ ){
		node = _engine->fsm_by_expecting_event_id[ i ];
		while( node != NULL ){
			ptr     = node->next;
			fsm_ind = (_fsm_tran_index_t *) node->data;

			//found a node containing #fsm
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
				mmt_mem_force_free( fsm_ind );//node->data

				mmt_mem_force_free( node );
			}
			node = ptr;
		}
	}

	//(2) - remove fsm from the list of instances
	//TODO: refine
//	_engine->total_instances_count -= count_nodes_from_link_list( _engine->fsm_by_instance_id[ fsm_id ] );
	_engine->fsm_by_instance_id[ fsm_id ] = remove_node_from_link_list(  _engine->fsm_by_instance_id[ fsm_id ], fsm );
	fsm_free( fsm );
}

static inline uint16_t _find_an_available_id( rule_engine_t *_engine ){
	size_t i;
	for( i=1; i<_engine->max_instances_size; i++ )
		if( _engine->fsm_by_instance_id[ i ] == NULL ){
			return i;
		}
	//not enough
	mmt_halt( "Not enough memory slots for fsm instances when verifying rule %d (%s:%d)", _engine->rule_info->id, __FILE__, __LINE__ );
	return 0;
}

static inline
enum verdict_type _process_a_node( link_node_t *node, uint16_t event_id, message_t *message_data, const void *event_data, rule_engine_t *_engine ){
	_fsm_tran_index_t *fsm_ind = node->data;
	fsm_t *fsm = fsm_ind->fsm;
	//fire a specific transition of the current state of #node->fsm
	//the transition has index = #node->tran_index
	enum fsm_handle_event_value val;
	fsm_t *new_fsm = NULL;
	uint16_t new_fsm_id;
	enum verdict_type verdict;

	//mmt_debug( "  transition to verify: %zu", fsm_ind->index );
	val = fsm_handle_event( fsm, fsm_ind->index, message_data, event_data, &new_fsm );

//	mmt_debug( "Verify transition: %zu of fsm %p", fsm_ind->index, fsm );

	//if the execution of the transition having index = fsm_ind->index creates a new fsm
	if( new_fsm != NULL ){
		//the new fsm being created is an instance of #fsm_bootstrap
		//=> put the new one to a new class
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

		fsm = new_fsm;
		fsm_set_user_data( fsm, _engine );
	}
	else{
		if( val == FSM_STATE_CHANGED ){
			//mmt_debug( "FSM_STATE_CHANGED" );

			//remove from old list
			//=> the #fsm_ind->fsm does not wait for the #event_id any more
			_engine->fsm_by_expecting_event_id[ event_id ] = remove_link_node_from_its_link_list( node, _engine->fsm_by_expecting_event_id[ event_id ] );

			//free the node
			mmt_mem_force_free( node );
			//free node->data
			mmt_mem_force_free( fsm_ind );
		}
	}

	switch( val ){
	case FSM_STATE_CHANGED:
		//mmt_debug( "FSM_STATE_CHANGED" );
		//add to new list(s) that waiting for a new event
		_set_expecting_events_id( _engine, fsm, new_fsm != NULL,  message_data->counter );
		break;

	//a final state that is either valid state or invalid one
	//depending on rule type (ATTACK, SECURITY, EVASION, ... ) a different verdict will be given
	case FSM_FINAL_STATE_REACHED:
	case FSM_ERROR_STATE_REACHED:
		verdict = _get_verdict( _engine->rule_info->type_id, val);

		if( verdict == VERDICT_UNKNOWN ){
			//remove the current fsm from validating list
			_reset_engine_for_instance( _engine, fsm );
		}else{
			_store_valid_execution_trace( _engine, fsm );
			//remove all fsm having the same id => stop validating this fsm and its instances (the other fsm having the same id)
			_reset_engine_for_fsm( _engine, fsm );
		}
		return verdict;

	case FSM_INCONCLUSIVE_STATE_REACHED:
		_reset_engine_for_instance( _engine, fsm );
		break;

#ifdef DEBUG_MODE
	case FSM_ERR_ARG:
		mmt_halt( "FSM_ERR_ARG" );
		break;
#endif

	default:
		break;
	}

	return VERDICT_UNKNOWN;
}

/**
 * Public API
 */
enum verdict_type rule_engine_process( rule_engine_t *engine, message_t *message ){
#ifdef DEBUG_MODE
	mmt_assert( engine != NULL,  "engine cannot be null" );
	mmt_assert( message != NULL, "message cannot be null" );
#endif
	return engine->processing_packets( engine, message );
}


enum verdict_type _process_single_packet( rule_engine_t *engine, message_t *message ){
	enum verdict_type verdict = VERDICT_UNKNOWN;
	const void *data = engine->rule_info->convert_message( message );
	enum fsm_handle_event_value val = fsm_handle_single_packet( engine->fsm_bootstrap, message, data );
	const mmt_array_t *array;
	size_t i;

	switch( val ){
	case FSM_NO_STATE_CHANGE:
		return VERDICT_UNKNOWN;

	//a final state that is either valid state or invalid one
	//depending on rule type (ATTACK, SECURITY, EVASION, ... ) a different verdict will be given
	case FSM_INCONCLUSIVE_STATE_REACHED:
	case FSM_FINAL_STATE_REACHED:
	case FSM_ERROR_STATE_REACHED:
		verdict = _get_verdict( engine->rule_info->type_id, val );

		if( verdict != VERDICT_UNKNOWN )
			_store_valid_execution_trace( engine, engine->fsm_bootstrap );

		//the message has been retained 2 times for 2 events of the #fsm_bootstrap
		free_message_ts( message, 2 );

		break;

	case FSM_ERR_ARG:
		mmt_halt( "FSM_ERR_ARG" );
		break;

	default:
		break;
	}


	return verdict;
}


enum verdict_type _process_multi_packets( rule_engine_t *engine, message_t *message ){
	const void *data    = engine->rule_info->convert_message( message );
	const uint64_t hash = engine->rule_info->hash_message( data );
	uint8_t event_id;
	link_node_t *node, *node_ptr;
	_fsm_tran_index_t *fsm_ind;
	enum verdict_type ret;


	//there are no transitions that can receive the message
	if( hash == 0 ){
		return VERDICT_UNKNOWN;
	}

	/**
	 * We need to store the head of each entry in #fsm_by_expecting_event_id
	 * as when verifying one event, a new fsm instance can be created and inserted
	 * to the head of one entry
	 * memcpy is slower than for-each
	 */
	//memcpy( _engine->tmp_fsm_by_expecting_event_id, _engine->fsm_by_expecting_event_id, _engine->max_events_count * sizeof( void *) );
	for( event_id=0; event_id<engine->max_events_size; event_id++ )
		engine->tmp_fsm_by_expecting_event_id[ event_id ] =  engine->fsm_by_expecting_event_id[event_id ];

	//mmt_debug( "Verify message counter: %"PRIu64", ts: %"PRIu64, message->counter, message->timestamp );
	//mmt_debug( "===Verify Rule %d=== %zu", _engine->rule_info->id, _engine->max_events_count );

	//get from hash table the list of events to be verified
	for( event_id=0; event_id<engine->max_events_size; event_id++ ){

		//this event does not fire
		if(  BIT_CHECK( hash, event_id ) == 0 ) continue;
		//mmt_debug( "Event_id : %d", event_id );

		//verify fsm instances that are waiting for event_id
		node = engine->tmp_fsm_by_expecting_event_id[ event_id ];

		//for each instance
		while( node != NULL ){

			fsm_ind  = (_fsm_tran_index_t *)node->data;
			node_ptr = node;
			node     = node->next;

			//put this after node = node->next
			// because #node can be freed( or inserted a new node) in the function #_fire_transition
			ret = _process_a_node( node_ptr, event_id, message, data, engine );

			//get only one verdict per packet
			if( ret != VERDICT_UNKNOWN ){
				return ret;
			}
		}
	}

	//check timeout
	//verify instances that are waiting for timeout
	node = engine->fsm_by_expecting_event_id[ FSM_EVENT_TYPE_TIMEOUT ];
	//mmt_debug( "Zero-nodes count: %zu", count_nodes_from_link_list(node));

	while( node != NULL ){

		fsm_ind  = (_fsm_tran_index_t *)node->data;
		node_ptr = node;
		node     = node->next;

		//check whether the #fsm_ind was verified above
		if( fsm_ind->counter == message->counter )
			continue;

		//put this after node = node->next
		// because #node can be freed( or inserted a new node) in the function #_fire_transition
		ret = _process_a_node( node_ptr, FSM_EVENT_TYPE_TIMEOUT, message, data, engine );

		//get only one verdict per packet
		if( ret != VERDICT_UNKNOWN ){
			return ret;
		}
	}

	return VERDICT_UNKNOWN;
}



/**
 * Public API
 */
rule_engine_t* rule_engine_init( const rule_info_t *rule_info, size_t max_instances_count ){
	size_t i;
	mmt_assert( rule_info != NULL, "rule_info is NULL");
	rule_engine_t *_engine = mmt_mem_alloc( sizeof( rule_engine_t ));

	_engine->fsm_bootstrap      = rule_info->create_instance();
	fsm_set_id( _engine->fsm_bootstrap, 0 );

	_engine->rule_info          = rule_info;
	_engine->max_events_size    = rule_info->events_count + 1; //event_id start from 1
	mmt_assert( _engine->max_events_size <= 64, "Cannot hold more than 64 events in a property" );
	_engine->max_instances_size = max_instances_count;
	_engine->instances_count    = 1; //fsm_bootstrap
	//linked-list of fsm instances indexed by their expected event_id
	_engine->tmp_fsm_by_expecting_event_id = mmt_mem_alloc( _engine->max_events_size * sizeof( void *) );
	_engine->fsm_by_expecting_event_id     = mmt_mem_alloc( _engine->max_events_size * sizeof( void *) );
	for( i=0; i<_engine->max_events_size; i++ )
		_engine->fsm_by_expecting_event_id[ i ] = NULL;

	//add fsm_bootstrap to the list
	_set_expecting_events_id( _engine, _engine->fsm_bootstrap, NO, 0 );

	//linked-list of fsm instances
	_engine->fsm_by_instance_id = mmt_mem_alloc( _engine->max_instances_size * sizeof( void *) );
	for( i=0; i<_engine->max_instances_size; i++ )
		_engine->fsm_by_instance_id[ i ] = NULL;

	//add fsm_bootstrap to the first element of
	_engine->fsm_by_instance_id[ 0 ] = insert_node_to_link_list(_engine->fsm_by_instance_id[ 0 ], _engine->fsm_bootstrap );

	_engine->valid_execution_trace = mmt_array_init( _engine->max_events_size );

	_engine->total_instances_count = 0;

	fsm_set_user_data( _engine->fsm_bootstrap, _engine );


	if( fsm_is_verifying_single_packet( _engine->fsm_bootstrap) ){
		_engine->processing_packets = _process_single_packet;
	}else{
		_engine->processing_packets = _process_multi_packets;
	}

	return _engine;
}


/**
 * Public API
 */
void rule_engine_free( rule_engine_t *_engine ){
	size_t i;

	__check_null( _engine, );

	for( i=0; i<_engine->max_events_size; i++ )
		free_link_list(_engine->fsm_by_expecting_event_id[ i ], YES );
	_engine->max_events_size = 0;

	mmt_mem_free( _engine->fsm_by_expecting_event_id );
	mmt_mem_free( _engine->tmp_fsm_by_expecting_event_id );

	for( i=0; i<_engine->max_instances_size; i++ )
		free_link_list_and_data( _engine->fsm_by_instance_id[ i ], (void *)fsm_free );

	mmt_mem_free( _engine->fsm_by_instance_id );

	if( _engine->valid_execution_trace != NULL )
		mmt_array_free( _engine->valid_execution_trace, (void *)free_message_t );

	mmt_mem_free( _engine );
}
