/*
 * mmt_fsm.c
 *
 *  Created on: 3 oct. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "mmt_fsm.h"
#include "mmt_alloc.h"
#include "data_struct.h"
#include "message_t.h"
/**
 * Detailed definition of FSM
 */
typedef struct fsm_struct{
	uint64_t timer;
	uint64_t counter;

   /**  Pointer to the current fsm_state_struct */
   const fsm_state_t *current_state;
   /**
    *  Pointer to previous fsm_state_struct
    *
    * The previous state is stored for convenience in case the user needs to
    * keep track of previous states.
    */
   const fsm_state_t *previous_state;
   /**
    *  Pointer to a state that will be entered whenever an error occurs in the machine.
    *
    * See #FSM_ERROR_STATE_REACHED for when the machine enters the error state.
    */
   const fsm_state_t *error_state;

   /**
    * Store initial state of the machine.
    * It is used only in #fsm_reset to restore the #current_state
    */
   const fsm_state_t *init_state;

   uint16_t id;
   /**
    * Trace of running FSM
    */
   mmt_map_t *events_trace; //map: <event_id : event_data>

   mmt_map_t *messages_trace;

}_fsm_t;

/**
 * Execute an entry
 */
//static void _exec_action( bool entry, const void *event_data, const fsm_state_t *state, _fsm_t *fsm ){
//	enum fsm_action_type action_type;
//	if( entry == YES )
//		action_type = state->entry_action;
//	else
//		action_type = state->exit_action;
//
//	switch( action_type ){
//		case FSM_ACTION_RESET_TIMER:
//			mmt_debug( "RESET TIMER ");
//			break;
//		default:
//			mmt_debug("Not good when calling this function with action_type = %d", action_type );
//	}
//}

/**
 * Public API
 */
fsm_t *fsm_init(const fsm_state_t *initial_state, const fsm_state_t *error_state, const fsm_state_t *final) {
	_fsm_t *fsm = mmt_mem_alloc( sizeof( _fsm_t ));

	fsm->init_state      = initial_state;
	fsm->current_state   = initial_state;
	fsm->previous_state  = NULL;
	fsm->error_state     = error_state;
	fsm->id              = 0;
	fsm->events_trace    = mmt_map_init( compare_uint16_t );
	fsm->messages_trace  = mmt_map_init( compare_uint16_t );
	return (fsm_t *) fsm;
}

/**
 * Public API
 */
void fsm_reset( fsm_t *fsm ){
	_fsm_t *_fsm;
	if( !fsm ) return;

	_fsm = (_fsm_t *)fsm;
	//reset the current state to the initial one
	_fsm->current_state  = _fsm->init_state;
	_fsm->previous_state = NULL;

	mmt_map_free_key_and_data( _fsm->events_trace, NULL, mmt_mem_free );
	_fsm->events_trace = mmt_map_init( compare_uint16_t );

	mmt_map_free_key_and_data( _fsm->messages_trace, NULL, (void *)free_message_t );
	_fsm->messages_trace = mmt_map_init( compare_uint16_t );
}

static inline _fsm_t* _fsm_clone( const _fsm_t *_fsm ){
	_fsm_t *new_fsm = mmt_mem_alloc( sizeof( _fsm_t ));
	new_fsm->id              = _fsm->id;
	new_fsm->init_state      = _fsm->init_state;
	new_fsm->current_state   = _fsm->current_state;
	new_fsm->previous_state  = _fsm->previous_state;
	new_fsm->error_state     = _fsm->error_state;
	new_fsm->events_trace    = mmt_map_clone_key_and_data( _fsm->events_trace, NULL, mmt_mem_retain );
	new_fsm->messages_trace  = mmt_map_clone_key_and_data( _fsm->messages_trace, NULL, (void *)retain_message_t );

	return new_fsm;
}

fsm_t *fsm_clone( const fsm_t *fsm ) {
	if( !fsm ) return NULL;
	return (fsm_t *) _fsm_clone( (_fsm_t *) fsm);
}


static inline enum fsm_handle_event_value _update_fsm( _fsm_t *_fsm, const fsm_state_t *new_state, const fsm_transition_t *tran, message_t *message_data, void *event_data ){
	void *ptr = NULL;
	//mmt_debug( "fsm_id = %d, ref = %zu, event_id: %d", _fsm->id, mmt_mem_reference_count( event_data), tran->event_type );

	ptr = mmt_map_set_data( _fsm->events_trace, (void *) &tran->event_type, mmt_mem_retain( event_data ), YES );
	//must free the old value
	mmt_mem_free( ptr );

	ptr = mmt_map_set_data( _fsm->messages_trace, (void *) &tran->event_type, retain_message_t( message_data ), YES );
	//must free the old value
	free_message_t( (message_t *) ptr );

//	/* Run exit action
//	 * (even if it returns to itself) */
//	if ( _fsm->current_state->exit_action != FSM_ACTION_DO_NOTHING  &&  _fsm->current_state->exit_action != FSM_ACTION_CREATE_INSTANCE )
//		_exec_action( NO, event_data, _fsm->current_state, _fsm );
//


	// Update the states in FSM
	_fsm->previous_state = _fsm->current_state;
	_fsm->current_state = new_state;

	/* Call the new _state's entry action if it has any
	 * (even if state returns to itself) */
	if ( new_state->entry_action == FSM_ACTION_UPDATE_TIMER || _fsm->previous_state->entry_action == FSM_ACTION_UPDATE_TIMER ){
		_fsm->counter = message_data->counter;
		_fsm->timer   = message_data->timestamp;
	}

	if (_fsm->current_state == _fsm->error_state)
		return FSM_ERROR_STATE_REACHED;

	/* If the target state is a final one, notify user that the machine has stopped */
	else if (!_fsm->current_state->transitions_count)
		return FSM_FINAL_STATE_REACHED;

	/* If the state returned to itself */
//	if (_fsm->current_state == _fsm->previous_state){
//		return FSM_STATE_LOOP_SELF;
//	}


	return FSM_STATE_CHANGED;
}


/**
 * Public API
 */
enum fsm_handle_event_value fsm_handle_event( fsm_t *fsm, uint16_t transition_index, message_t *message_data, void *event_data, fsm_t **new_fsm ) {
	const fsm_transition_t *tran = NULL;
	_fsm_t *_fsm = NULL, *_new_fsm = NULL;
	uint64_t timer, counter;

	//set the
	*new_fsm = NULL;
	if (!fsm ) return FSM_ERR_ARG;

	_fsm = (_fsm_t *)fsm;
	if (!_fsm->current_state) {
		//_go_to_error_state(_fsm, event);
		return FSM_ERROR_STATE_REACHED;
	}
	//no outgoing transitions
	if (!_fsm->current_state->transitions_count )
		return FSM_NO_STATE_CHANGE;
	if( _fsm->current_state->transitions_count <= transition_index )
		return FSM_ERR_ARG;

	//check if timeout
	tran = &_fsm->current_state->transitions[ 0 ];//timeout transition must be the first in the array
	if( tran->event_type == FSM_EVENT_TYPE_TIMEOUT ){
		timer = message_data->timestamp - _fsm->timer;
//		mmt_log( WARN, "Timeout out: %"PRIu64", max: %"PRIu64, timer, _fsm->current_state->delay.time_max);
		//timeout
		if( //_fsm->current_state->delay.counter_min < (message_data->counter - _fsm->counter)
				//&& (message_data->counter - _fsm->counter) < _fsm->current_state->delay.counter_max
				//&&
				_fsm->current_state->delay.time_min <= timer//for delay_min, sign = +1 means strictly greater
				&& timer <= _fsm->current_state->delay.time_max //for delay_max, sign = -1 means less than
			)
			;//it's OK ==>in the permetted delay
		else
			//fire timeout transition
			return _update_fsm( _fsm, tran->target_state, tran, message_data, event_data );
	}

	tran = &_fsm->current_state->transitions[ transition_index ];// _get_transition(_fsm, state, event);
	//must not be null
//	if( tran == NULL )
//		return FSM_NO_STATE_CHANGE;

	/* If transition is guarded, ensure that the condition is held: */
	if (tran->guard != NULL && tran->guard( event_data, (fsm_t *)fsm)  == NO )
			return FSM_NO_STATE_CHANGE;

	/* A transition must have a next _state defined
	 * If the user has not defined the next _state, go to error _state: */
	//mmt_assert( tran->target_state != NULL, "Error: Target state cannot be NULL" );

//	mmt_debug( "Exit action: %d", _fsm->current_state->exit_action );
	//Create a new instance, then update its data
	if ( tran->action == FSM_ACTION_CREATE_INSTANCE ){

		_new_fsm = _fsm_clone( _fsm );
		*new_fsm = (fsm_t *)_new_fsm;
		return _update_fsm( _new_fsm, tran->target_state, tran, message_data, event_data );
	}
	//add event to execution trace
	return _update_fsm( _fsm, tran->target_state, tran, message_data, event_data );

}

/**
 * Public API
 */
const fsm_state_t *fsm_get_current_state( const fsm_t *fsm) {
	if (!fsm) return NULL;

	return ((_fsm_t *)fsm)->current_state;
}

/**
 * Public API
 */
const fsm_state_t *fsm_get_previous_state( const fsm_t *fsm) {
	if (!fsm) return NULL;

	return ((_fsm_t *)fsm)->previous_state;
}

/**
 * Public API
 */
bool fsm_is_stopped( const fsm_t *fsm) {
	if (!fsm) return YES;
	return ((_fsm_t *)fsm)->current_state->transitions_count == 0;
}

/**
 * Public API
 */
void fsm_free( fsm_t *fsm ){
	_fsm_t *_fsm;
	if ( fsm == NULL ) return;

	_fsm = (_fsm_t *)fsm;

	mmt_map_free_key_and_data( _fsm->events_trace, NULL, mmt_mem_free );
	mmt_map_free_key_and_data( _fsm->messages_trace, NULL, (void *)free_message_t );
	mmt_mem_free( fsm );
}


/**
 * Public API
 */
mmt_map_t* fsm_get_execution_trace( const fsm_t *fsm ){
	_fsm_t *_fsm;
	if ( fsm == NULL ) return NULL;

	_fsm = (_fsm_t *)fsm;
	return( _fsm->messages_trace );
}


/**
 * Public API
 */
void *fsm_get_history( const fsm_t *fsm, uint32_t event_id ){
	_fsm_t *_fsm;
	void *data;
	if ( fsm == NULL ) return NULL;

	_fsm = (_fsm_t *)fsm;
	data = mmt_map_get_data( _fsm->events_trace, &event_id );
	//mmt_debug("Get history %d: %s", event_id, data == NULL? "NUL": "not NULL" );
	return data;
}

/**
 * Public API
 */
uint16_t fsm_get_id( const fsm_t *fsm ){
	_fsm_t *_fsm;
	if ( fsm == NULL ) return -1;
	_fsm = (_fsm_t *)fsm;
	return _fsm->id;
}

/**
 * Public API
 */
void fsm_set_id( fsm_t *fsm, uint16_t id ){
	_fsm_t *_fsm;
	if ( fsm == NULL ) return;
	_fsm = (_fsm_t *)fsm;
	_fsm->id = id;
}

/**
 * Public API
 */
void fsm_get_timer_and_counter( const fsm_t *fsm, uint64_t *timer, uint64_t *counter ){
	_fsm_t *_fsm;
	if ( fsm == NULL ) return;
	_fsm = (_fsm_t *)fsm;

	*timer   = _fsm->timer;
	*counter = _fsm->counter;
}
