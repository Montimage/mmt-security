/*
 * mmt_fsm.c
 *
 *  Created on: 3 oct. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "mmt_fsm.h"
#include "mmt_alloc.h"
#include "data_struct.h"

/**
 * Detailed definition of FSM
 */
typedef struct fsm_struct{
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

   /**
    * Trace of running FSM
    */
   mmt_map_t *execution_trace; //map: <event_id : event_data>
}_fsm_t;

/**
 * Execute an entry
 */
void _exec_action( enum bool entry, const fsm_event_t *event, fsm_state_t *state, _fsm_t *fsm ){
	enum fsm_action_type action_type;
	if( entry == YES )
		action_type = state->entry_action;
	else
		action_type = state->exit_action;

	switch( action_type ){
		case FSM_ACTION_CREATE_INSTANCE:
			mmt_debug(" CREATE new INSTANCE ");
			break;
		case FSM_ACTION_RESET_TIMER:
			mmt_debug( "RESET TIMER ");
			break;
		default:
			mmt_debug("Not good when calling this function with action_type = %d", action_type );
	}
}

static void _go_to_error_state( _fsm_t *fsm, const fsm_event_t * event) {
	fsm->previous_state = fsm->current_state;
	fsm->current_state  = fsm->error_state;

	if (fsm->current_state && fsm->current_state->entry_action != FSM_ACTION_DO_NOTHING )
		_exec_action( YES, event, fsm->current_state, fsm );
}


static fsm_transition_t *_get_transition( const _fsm_t *fsm, const fsm_state_t *state,
		const fsm_event_t * event) {
	size_t i;
	fsm_transition_t *tran = NULL;
mmt_debug( "state %s", state->description );
	for (i = 0; i < state->transitions_count; ++i) {
		tran = &state->transitions[i];
mmt_debug( " - trans %zu", i );
		/* A transition for the given event has been found: */
		if (tran->event_type == event->type) {
			if (!tran->guard)
				return tran;
			/* If transition is guarded, ensure that the condition is held: */
			else if (tran->guard( event, (fsm_t *)fsm) )
				return tran;
		}
	}

	/* No transitions found for given event for given _state: */
	return NULL;
}

void fsm_update_execution_trace( _fsm_t *fsm, const void *data ){

}

/**
 * Public API
 */
fsm_t *fsm_init(const fsm_state_t *initial_state, const fsm_state_t *error_state, const fsm_state_t *final) {
	_fsm_t *fsm = mmt_malloc( sizeof( _fsm_t ));

	fsm->init_state     = initial_state;
	fsm->current_state  = initial_state;
	fsm->previous_state = NULL;
	fsm->error_state    = error_state;

	fsm->execution_trace = mmt_map_init( compare_uint16_t );
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

	mmt_map_free( _fsm->execution_trace, NO );
	_fsm->execution_trace = mmt_map_init( compare_uint16_t );
}


fsm_t *fsm_clone( const fsm_t *fsm ) {
	size_t i;
	_fsm_t *_fsm;
	if( !fsm ) return NULL;
	_fsm = (_fsm_t *)fsm;

	_fsm_t *new_fsm = mmt_malloc( sizeof( _fsm_t ));

	new_fsm->init_state      = _fsm->init_state;
	new_fsm->current_state   = _fsm->current_state;
	new_fsm->previous_state  = _fsm->previous_state;
	new_fsm->error_state     = _fsm->error_state;
	new_fsm->execution_trace = mmt_map_clone( _fsm->execution_trace );
	return (fsm_t *) new_fsm;
}


/**
 * Public API
 */
enum fsm_handle_event_value fsm_handle_event( fsm_t *fsm, const fsm_event_t *event) {
	fsm_transition_t *tran = NULL;
	const fsm_state_t *state = NULL;
	_fsm_t *_fsm = NULL;
	if (!fsm || !event)
		return FSM_ERR_ARG;

	_fsm = (_fsm_t *)fsm;
	if (!_fsm->current_state) {
		_go_to_error_state(_fsm, event);
		return FSM_ERROR_STATE_REACHED;
	}
	//no outgoing transitions
	if (!_fsm->current_state->transitions_count )
		return FSM_NO_STATE_CHANGE;

	state = _fsm->current_state;
	do {
		tran = _get_transition(_fsm, state, event);

		//no transitions are satisfied
		if( tran == NULL )
			return FSM_NO_STATE_CHANGE;

		/* A transition must have a next _state defined. If the user has not
		 * defined the next _state, go to error _state: */
		if (!tran->target_state) {
			_go_to_error_state(_fsm, event);
			return FSM_ERROR_STATE_REACHED;
		}

		state = tran->target_state;

		/* Run exit action only if the current state is left
		 * (even if it returns to itself) */
		if ( _fsm->current_state->exit_action != FSM_ACTION_DO_NOTHING )
			_exec_action( NO, event, _fsm->current_state, _fsm );

		/* Call the new _state's entry action if it has any
		 * (even if state returns to itself) */
		if ( state->entry_action != FSM_ACTION_DO_NOTHING )
			_exec_action( YES, event, state, _fsm );

		// Update the states in FSM
		_fsm->previous_state = _fsm->current_state;
		_fsm->current_state = state;

		/* If the state returned to itself */
		if (_fsm->current_state == _fsm->previous_state)
			return FSM_STATE_LOOP_SELF;

		if (_fsm->current_state == _fsm->error_state)
			return FSM_ERROR_STATE_REACHED;

		/* If the target state is a final one, notify user that the machine has stopped */
		if (!_fsm->current_state->transitions_count)
			return FSM_FINAL_STATE_REACHED;

		return FSM_STATE_CHANGED;
	}
	while (state);

	return FSM_NO_STATE_CHANGE;
}

/**
 * Public API
 */
const fsm_state_t *fsm_current_state( const fsm_t *fsm) {
	if (!fsm) return NULL;

	return ((_fsm_t *)fsm)->current_state;
}

/**
 * Public API
 */
const fsm_state_t *fsm_previous_state( const fsm_t *fsm) {
	if (!fsm) return NULL;

	return ((_fsm_t *)fsm)->previous_state;
}

/**
 * Public API
 */
enum bool fsm_is_stopped( const fsm_t *fsm) {
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

	mmt_map_free( _fsm->execution_trace, NO );
	mmt_free( fsm );
}


/**
 * Public API
 */
mmt_map_t* fsm_get_execution_trace( const fsm_t *fsm ){
	_fsm_t *_fsm;
	if ( fsm == NULL ) return NULL;

	_fsm = (_fsm_t *)fsm;
	return( _fsm->execution_trace );
}


void *fsm_get_history( const fsm_t *fsm, uint32_t event_id ){
	_fsm_t *_fsm;
	if ( fsm == NULL ) return NULL;

	mmt_debug("Get history %d", event_id );

	_fsm = (_fsm_t *)fsm;
	return mmt_map_get_data( _fsm->execution_trace, &event_id );
}

void fsm_create_new_instance( void *event_data, const fsm_event_t *event, const fsm_t *fsm){

}
