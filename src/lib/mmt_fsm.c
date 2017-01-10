/*
 * mmt_fsm.c
 *
 *  Created on: 3 oct. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "mmt_lib.h"

#include "mmt_fsm.h"
#include "message_t.h"

/**
 * Detailed definition of FSM
 */
typedef struct fsm_struct{
	uint16_t id;

	uint64_t time_min, time_max;
	uint64_t counter_min, counter_max;

	/** ID of event to be verified */
	uint16_t current_event_id;

   /**  Pointer to the current fsm_state_struct */
   const fsm_state_t *current_state;
   /**
    *  Pointer to previous fsm_state_struct
    *
    * The previous state is stored for convenience in case the user needs to
    * keep track of previous states.
    */
   const fsm_state_t *previous_state;

   const fsm_state_t *init_state;

   const fsm_state_t *error_state;

   const fsm_state_t *incl_state;

   const fsm_state_t *success_state;


   /**
    * Trace of running FSM
    */
   mmt_array_t *events_trace; //map: <event_id : event_data>

   mmt_array_t *messages_trace;
}_fsm_t;


/**
 * Public API
 */
fsm_t *fsm_init(const fsm_state_t *initial_state, const fsm_state_t *error_state, const fsm_state_t *final, const fsm_state_t *incl_state, size_t events_count ) {
	_fsm_t *fsm = mmt_mem_alloc( sizeof( _fsm_t ));

	fsm->init_state      = initial_state;
	fsm->current_state   = initial_state;
	fsm->previous_state  = NULL;
	fsm->error_state     = error_state;
	fsm->incl_state      = incl_state;
	fsm->success_state   = final;
	fsm->id              = 0;
	fsm->events_trace    = mmt_array_init( events_count + 1 ); //event_id starts from 1, zero is timeout
	fsm->messages_trace  = mmt_array_init( events_count + 1 ); //event_id starts from 1, zero is timeout
	fsm->time_max    = fsm->time_min    = 0;
	fsm->counter_max = fsm->counter_min = 0;
	fsm->current_event_id = 0;

	return (fsm_t *) fsm;
}

/**
 * Public API
 */
void fsm_reset( fsm_t *fsm ){
	_fsm_t *_fsm;
	size_t i;
	__check_null( fsm, );

	_fsm = (_fsm_t *)fsm;
	//reset the current state to the initial one
	_fsm->current_state    = _fsm->init_state;
	_fsm->previous_state   = NULL;
	_fsm->current_event_id = 0;

	for( i=0; i< _fsm->events_trace->elements_count; i++ ){
		mmt_free_and_assign_to_null( _fsm->events_trace->data[ i ]   );
		mmt_free_and_assign_to_null( _fsm->messages_trace->data[ i ] );
	}
}

static inline _fsm_t* _fsm_clone( const _fsm_t *_fsm ){

	_fsm_t *new_fsm = mmt_mem_dup( _fsm, sizeof( _fsm_t) );

	new_fsm->events_trace    = mmt_array_clone( _fsm->events_trace,   mmt_mem_retain );
	new_fsm->messages_trace  = mmt_array_clone( _fsm->messages_trace, (void *)retain_message_t );

	return new_fsm;
}

fsm_t *fsm_clone( const fsm_t *fsm ) {
	__check_null( fsm, NULL );
	return (fsm_t *) _fsm_clone( (_fsm_t *) fsm);
}

static inline enum fsm_handle_event_value _fire_a_tran( fsm_t *fsm, uint16_t transition_index, message_t *message_data, void *event_data ) {
	fsm_t *new_fsm = NULL;
	enum fsm_handle_event_value ret;

	ret = fsm_handle_event( fsm,  transition_index, message_data, event_data, &new_fsm );

	//Occasionally a new fsm may be created, we do not need it
	if( unlikely( new_fsm != NULL ) ) fsm_free( new_fsm );

	return ret;
}


static inline enum fsm_handle_event_value _update_fsm( _fsm_t *_fsm, const fsm_state_t *new_state, const fsm_transition_t *tran, message_t *message_data, void *event_data ){
	void *ptr = NULL;
	uint64_t val;
	size_t i;
	enum fsm_handle_event_value ret;

#ifdef DEBUG_MODE
	if( unlikely( _fsm->current_event_id == 0 )){
		mmt_halt( "Not possible");
	}
#endif

	//mmt_debug( "fsm_id = %d (%p), ref = %zu, event_id: %d", _fsm->id, _fsm, mmt_mem_reference_count( event_data), tran->event_type );

	//check if we will override an element of execution trace
	if( unlikely( _fsm->events_trace->data[ _fsm->current_event_id   ] != NULL ) ){
		mmt_mem_free( _fsm->events_trace->data[ _fsm->current_event_id   ] );
	//if( unlikely( _fsm->messages_trace->data[ _fsm->current_event_id   ] != NULL ) )
		free_message_t( _fsm->messages_trace->data[ _fsm->current_event_id   ] );
	}

	//store execution log
	_fsm->events_trace->data[ _fsm->current_event_id   ] = mmt_mem_retain( event_data );
	_fsm->messages_trace->data[ _fsm->current_event_id ] = retain_message_t( message_data );

//	/* Run exit action
//	 * (even if it returns to itself) */
//		_exec_action( NO, event_data, _fsm->current_state, _fsm );
//

	// Update the states in FSM
	_fsm->previous_state = _fsm->current_state;
	_fsm->current_state  = new_state;

	/* If the target state is a final one, notify user that the machine has stopped */
	if (_fsm->current_state == _fsm->error_state){
		//mmt_debug("FSM_ERROR_STATE_REACHED" );
		return FSM_ERROR_STATE_REACHED;
	}else if (_fsm->current_state == _fsm->incl_state){
		//mmt_debug("FSM_INCONCLUSIVE_STATE_REACHED" );
		return FSM_INCONCLUSIVE_STATE_REACHED;
	}else if ( _fsm->current_state == _fsm->success_state ){
		//mmt_debug("FSM_FINAL_STATE_REACHED" );
		return FSM_FINAL_STATE_REACHED;
	}else if( _fsm->current_state->transitions_count == 0 )
		return FSM_ERROR_STATE_REACHED;

	// We reach a state in which has delay = 0
	// => we need to continue verifying the next outgoing transitions
	//    against the current message_data and event_data
	if( new_state->is_temporary ){
		//for each outgoing transition of the target
		for( i=0; i<new_state->transitions_count; i++ ){
			//fire the timeout transition only if other transitions cannot be fired
			if( new_state->transitions[i].event_type == FSM_EVENT_TYPE_TIMEOUT )
				continue;

			ret = _fire_a_tran( (fsm_t *) _fsm, (uint16_t)i, message_data, event_data );

			if( ret != FSM_NO_STATE_CHANGE )
				return ret;
		}

		//fire timeout transition only if we cannot find any other outgoing transitions
		if( new_state->transitions[0].event_type == FSM_EVENT_TYPE_TIMEOUT )
			return _fire_a_tran( (fsm_t *) _fsm, 0, message_data, event_data );

		mmt_debug( "LOOOP" );
		return FSM_NO_STATE_CHANGE;
	}

	//update deadline
	//outgoing from init state
	if( tran->action == FSM_ACTION_RESET_TIMER || _fsm->previous_state == _fsm->init_state ){
		_fsm->counter_min = new_state->delay.counter_min + message_data->counter;
		_fsm->time_min    = new_state->delay.time_min    + message_data->timestamp;

		_fsm->counter_max = new_state->delay.counter_max + message_data->counter;
		_fsm->time_max    = new_state->delay.time_max    + message_data->timestamp;
	}else{
		val = new_state->delay.counter_min + message_data->counter;
		if( val > _fsm->counter_min ) _fsm->counter_min = val;

		val = new_state->delay.time_min + message_data->timestamp;
		if( val > _fsm->time_min ) _fsm->time_min = val;

		val = new_state->delay.counter_max + message_data->counter;
		if( val < _fsm->counter_max ) _fsm->counter_max = val;

		val = new_state->delay.time_max + message_data->timestamp;
		if( val < _fsm->time_max ) _fsm->time_max = val;
	}
	/* Call the new _state's entry action if it has any
	 * (even if state returns to itself) */

	//mmt_debug("FSM_STATE_CHANGED" );
	return FSM_STATE_CHANGED;
}


/**
 * Public API
 */
enum fsm_handle_event_value fsm_handle_event( fsm_t *fsm, uint16_t transition_index, message_t *message_data, void *event_data, fsm_t **new_fsm ) {
	const fsm_transition_t *tran;
	_fsm_t *_fsm, *_new_fsm;
	//uint64_t timer, counter;

#ifdef DEBUG_MODE
	__check_null( fsm, FSM_ERR_ARG );
#endif

	_fsm = (_fsm_t *)fsm;

#ifdef DEBUG_MODE
	if ( unlikely( !_fsm->current_state ))
		mmt_halt( "Not found current state of fsm %d", _fsm->id );
#endif

	//	mmt_debug( "Verify transition: %d of fsm %p", transition_index, fsm );

	//do not use the message/event if it comes early than time_min
	if( message_data->timestamp < _fsm->time_min )
		return FSM_NO_STATE_CHANGE;

	//event_type = FSM_EVENT_TYPE_TIMEOUT when this function is called by #_fire_a_tran
	//e.g., when no real-transition can be fired
	//in such a case, event_id will be the last transition that can not be fire
	if( _fsm->current_state->transitions[ transition_index ].event_type != FSM_EVENT_TYPE_TIMEOUT )
		_fsm->current_event_id = _fsm->current_state->transitions[ transition_index ].event_type;

	//check if timeout or not (even we are checking a real event)
	//check only for the state other than init_state
	if( _fsm->current_state != _fsm->init_state && message_data->timestamp > _fsm->time_max &&  !_fsm->current_state->is_temporary  ){
		tran = &_fsm->current_state->transitions[ 0 ];//timeout transition must be the first in the array
		if( likely( tran->event_type == FSM_EVENT_TYPE_TIMEOUT ))
			//fire timeout transition
			return _update_fsm( _fsm, tran->target_state, tran, message_data, event_data );
	}

	tran = &_fsm->current_state->transitions[ transition_index ];// _get_transition(_fsm, state, event);

	//if we intend to check TIMEOUT but fsm is not timeout => stop checking
	if( tran->event_type == FSM_EVENT_TYPE_TIMEOUT )
		return FSM_NO_STATE_CHANGE;


	//must not be null
//	if( tran == NULL ) return FSM_NO_STATE_CHANGE;

	/* If transition is guarded, ensure that the condition is held: */
	if (tran->guard != NULL && tran->guard( event_data, fsm)  == NO )
		return FSM_NO_STATE_CHANGE;

	/* A transition must have a next _state defined
	 * If the user has not defined the next _state, go to error _state: */
	//mmt_assert( tran->target_state != NULL, "Error: Target state cannot be NULL" );

//	mmt_debug( "Exit action: %d", _fsm->current_state->exit_action );
	//Create a new instance, then update its data
	if ( tran->action == FSM_ACTION_CREATE_INSTANCE ){
		//mmt_debug( " new FSM");
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
	__check_null( fsm, NULL );

	return ((_fsm_t *)fsm)->current_state;
}

/**
 * Public API
 */
const fsm_state_t *fsm_get_previous_state( const fsm_t *fsm) {
	__check_null( fsm, NULL );

	return ((_fsm_t *)fsm)->previous_state;
}

/**
 * Public API
 */
bool fsm_is_stopped( const fsm_t *fsm) {
	__check_null( fsm, YES );
	return ((_fsm_t *)fsm)->current_state->transitions_count == 0;
}

/**
 * Public API
 */
void fsm_free( fsm_t *fsm ){
	_fsm_t *_fsm;
	__check_null( fsm, );

	_fsm = (_fsm_t *)fsm;

	mmt_array_free( _fsm->events_trace,   (void *)mmt_mem_free );
	mmt_array_free( _fsm->messages_trace, (void *)free_message_t );
	mmt_mem_free( fsm );
}


/**
 * Public API
 */
const mmt_array_t* fsm_get_execution_trace( const fsm_t *fsm ){
	_fsm_t *_fsm;
#ifdef DEBUG_MODE
	__check_null( fsm, NULL );
#endif
	_fsm = (_fsm_t *)fsm;
	return( _fsm->messages_trace );
}


/**
 * Public API
 */
const void *fsm_get_history( const fsm_t *fsm, uint32_t event_id ){
	_fsm_t *_fsm;
#ifdef DEBUG_MODE
	__check_null( fsm, NULL );
#endif
	_fsm = (_fsm_t *)fsm;
	return _fsm->events_trace->data[ event_id ];
}

/**
 * Public API
 */
inline uint16_t fsm_get_id( const fsm_t *fsm ){
	_fsm_t *_fsm;
#ifdef DEBUG_MODE
	__check_null( fsm, -1 );
#endif
	_fsm = (_fsm_t *)fsm;
	return _fsm->id;
}

/**
 * Public API
 */
inline void fsm_set_id( fsm_t *fsm, uint16_t id ){
	_fsm_t *_fsm;
#ifdef DEBUG_MODE
	__check_null( fsm,  );
#endif
	_fsm = (_fsm_t *)fsm;
	_fsm->id = id;
}
