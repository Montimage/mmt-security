/*
 * mmt_fsm.h
 *
 *  Created on: 3 oct. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 * This is a simple finite fsm_state_struct machine implementation.
 * It supports grouped states, guarded transitions, events
 * with payload, entry and exit actions, transition actions and access to
 * user-defined state data from all actions.
 *
 * The user must build the state machine by linking together states and
 * transitions arrays with pointers.
 * A pointer to an initial state and an error state are given to fsm_init()
 * to initialize a machine object.
 *
 * The machine is run by passing events to it with the function fsm_handle_event().
 * The return value of the function will give an indication to what has happened.
 * https://github.com/misje/stateMachine
 */

#ifndef SRC_LIB_FSM_H_
#define SRC_LIB_FSM_H_


#include "base.h"
#include "rule.h"
#include "mmt_alloc.h"
#include "message_t.h"

typedef struct fsm_delay_struct{
	/**
	 * Defines the validity period ([time_min, time_max]) of the left branch (e.g. context).
	 * Unit: micro-second.
	 * default is 0,
	 * - if value is < 0 then event needs to be satisfied before,
	 * - if = 0 then in same packet,
	 * - if > 0 then after
	 */
	uint64_t time_min, time_max;
	int time_min_sign, time_max_sign;
	/**
	 * Similar to [time_min, time_max] we can de ne [counter_min, counter_max] where the unit is the number of packets analysed.
	 * note that either delay or counter needs to be used not both
	 */
	uint64_t counter_min, counter_max;
	int counter_min_sign, counter_max_sign;
}fsm_delay_t;
/**
 *  Finite State Machine
 */
typedef void fsm_t;

#define FSM_EVENT_TYPE_TIMEOUT 0

enum fsm_action_type {
	FSM_ACTION_DO_NOTHING,
	FSM_ACTION_CREATE_INSTANCE,
};

/**
 * Events trigger transitions from a state to another.
 * Event types are defined by the user.
 * Any event may optionally contain a user-defined date.
 *
 */
typedef struct fsm_event_struct{
   /** Type of event. Defined by user. */
   uint16_t type;
   /**
    * Event payload.
    *
    * How this is used is entirely up to the user.
    * This data is always passed together with #type in order to make it possible
    * to always cast the data correctly.
    */
   void *data;
}fsm_event_t;

/* pre-defined state that will be detailed later */
struct fsm_state_struct;

/**
 * Outgoing transition from a state to another state.
 *
 * All states that are not final must have at least one transition.
 * The transition may be guarded or not.
 * Transitions are triggered by events.
 * If a state has more than one transition with the same type of event (and the
 * same condition), the first transition in the array will be run.
 * An unconditional transition placed last in the transition array of a state can
 * act as a "catch-all".
 * A transition may optionally run an #action,
 * which will have the triggering event passed to it as an argument, along with the
 * current and new states' data.
 *
 * It is perfectly valid for a transition to return to the state it belongs to.
 * Such a transition will not call the states's #entry_action or #exit_action.
 * If there are no transitions for the current event,
 * the state's parent will be handed the event.
 *
 * ### Examples ###
 * - An unguarded transition to a state with no action performed:
 * ~~~{.c}
 * {
 *    .event_type = EVENT_TIMEOUT,
 *    .condition = NULL,
 *    .guard = NULL,
 *    .action = NULL,
 *    .target_state = &main_menu_state,
 * },
 * ~~~
 * - A guarded transition executing an action
 * ~~~{.c}
 * {
 *    .event_type = EVENT_KEYBOARD,
 *    .condition = NULL,
 *    .guard = &ensure_numeric_input,
 *    .action = &addToBuffer,
 *    .target_state = &awaiting_input_state,
 * },
 * ~~~
 * - A guarded transition using a condition
 * ~~~{.c}
 * {
 *    .event_type = EVENT_MOUSE,
 *    .condition = box_limits,
 *    .guard = &coord_limits,
 * },
 * ~~~
 * By using "conditions" a more general guard function can be used,
 * operating on the supplied argument #condition. In this example,
 * #coord_limits checks whether the coordinates in the mouse event
 * are within the limits of the "box".
 *
 */
typedef struct fsm_transition_struct
{
   /**  The event that will trigger this transition. */
   uint16_t event_type;
   /**
    *  Check if data passed with event fulfills a condition.
    *
    * A transition may be conditional. If so, this function, if non-NULL, will
    * be called. Its first argument will be supplied with #condition, which
    * can be compared against the #payload in the #event.
    * One may choose to use this argument or not.
    * Only if the result is true, the transition will take place.
    *
    * - Input:
    *		+ condition event (data) to compare the incoming event against.
    * 	+ event the event passed to the fsm_state_struct machine.
    *		+ fsm the fsm containing this transition
    * - Return
    * 	+ YES if the event's data fulfills the condition, otherwise NO.
    */
   int ( *guard )( const void *event_data, const fsm_t *fsm );

   int action;
   /**
    *  The next state
    *
    * This must point to the next state that will be entered. It cannot be NULL.
    * If it is, the machine will detect it and enter the #error_state.
    */
   struct fsm_state_struct *target_state;
}fsm_transition_t;

/**
 *  States of machine
 *
 * The current state in a machine moves to a new state when one of the
 * #transitions in the current state triggers on an event.
 * An optional #exit_action is called when the state is left,
 * 	and an #entry_action is called when the machine enters a new state.
 * If a state returns to itself, neither #exit_action nor #entry_action
 * will be called.
 *
 * States may be organized in a hierarchy by setting #parent_state.
 * When a group/parent state is entered, the machine is
 * redirected to the group state's #entry_state (if non-NULL).
 * If an event does not trigger any transition in a state and if the
 * state has a parent, the event will be passed to the parent state.
 * This behavior is repeated for all parents. Thus all children of a state
 * have a set of common #transitions. A parent state's #entry_action will not
 * be called if an event is passed on to a child state.
 *
 * The following lists the different types of states that may be created, and
 * how to create them:
 *
 * ### Normal state ###
 * ~~~{.c}
 * fsm_state_t normal_state = {
 *    .parent_state = &group_state,
 *    .entry_state = NULL,
 *    .transition = (fsm_transition_t[]){
 *       { EVENT_KEYBOARD, (void *)(intptr_t)'\n', &compare_char, NULL, &target_state },
 *    },
 *    .transitions_count = 1,
 *    .data = NULL,
 *    .entry_action = &do_sth,
 *    .exit_action = &clean_up,
 * };
 * ~~~
 * In this example, `normal_state` is a child of `group_state`, but the
 * #parent_state value may also be NULL to indicate that it is not a child of
 * any group state.
 *
 * ### Group/parent state ###
 * A state becomes a group/parent state when it is linked to by child states
 * by using #parent_state. No members in the group state need to be set in a
 * particular way.
 * A parent state may also have a parent.
 * ~~~{.c}
 * fsm_state_t group_state = {
 *    .entry_state = &normal_state,
 *    .entry_action = NULL,
 * ~~~
 * If there are any transitions in the machine that lead to a group state,
 * it makes sense to define an entry state in the group. This can be
 * done by using #entry_state, but it is not mandatory. If the #entry_state
 * state has children, the chain of children will be traversed until a child
 * with its #entry_state set to NULL is found.
 *
 * - Note:
 * 	If #entry_state is defined for a group state, the group state's
 * 	#entry_action will not be called (the state pointed to by #entry_state (after
 * 	following the chain of children), however, will have its #entry_action
 * 	called).
 *
 * -Warning:
 * 	The machine cannot detect cycles in parent chains and children chains.
 * 	If such cycles are present, fsm_handle_event() will
 * 	never finish due to never-ending loops.
 *
 * ### Final state ###
 * A final state is a state that terminates the machine. A state is
 * considered as a final one if its #transitions_count is 0:
 * ~~~{.c}
 * fsm_state_t final_state = {
 *    .transitions = NULL,
 *    .transitions_count = 0,
 * ~~~
 * The error state used by the machine to indicate errors should be a final state.
 * Any calls to fsm_handle_event() when the current state is a
 * final one will return #FSM_NO_STATE_CHANGE.
 *
 */
typedef struct fsm_state_struct{
	const fsm_delay_t delay;

	char *description;

   /**
    *  An array of outgoing transitions of the state.
    */
   const struct fsm_transition_struct *transitions;
   /**
    *  Number of outgoing transitions in the #transitions array above.
    */
   size_t transitions_count;
   /**
    *  Data that will be available in its #entry_action and #exit_action
    */
   void *data;
   /**
    *  This function is called whenever the state is being entered. May be NULL.
    */
   int entry_action;
   /**
    *  This function is called whenever the state is being left. May be NULL.
    */
   int exit_action;
}fsm_state_t;


/**
 *  Initialize the machine
 *
 * This function creates and initializes the states. No actions are performed until
 * fsm_handle_event() is called.
 *
 * - Note:
 * 	 The #entry_action for #init_state will not be called.
 *
 *		 If init_state is a parent state with its #entry_state defined,
 *		 it will not be entered. One must explicitly set the initial state.
 *
 * - Input:
 * 	+ init_state the initial state of the machine.
 * 	+ error_state pointer to a state that acts a final state and notifies
 * 		the system/user that an error has occurred.
 * 	+ final_state
 * 	+ incl_state
 */
fsm_t *fsm_init( const fsm_state_t *init_state, const fsm_state_t *error_state, const fsm_state_t *final, const fsm_state_t *incl_state );

/**
 * Reset the machine to #init_state and #error_state as being initialized.
 *
 * It is safe to call this function numerous
 * times, for instance in order to reset/restart the machine if a final
 * state has been reached.
 *
 * - Input:
 * 	+ fsm: the machine to be reseted
 */
void fsm_reset( fsm_t *fsm );

/**
 *  fsm_handle_event() return values
 */
enum fsm_handle_event_value{
   /**  Erroneous arguments were passed */
	FSM_ERR_ARG = -2,
   /**
    *  The error state was reached
    *
    * This value is returned either when the machine enters the error state
    *  itself as a result of an error, or when the error state is the
    *  target state as a result of a successful transition.
    *
    * The machine enters the state machine if any of the following
    * happens:
    * - The current state is NULL
    * - A transition for the current event did not define the target state
    */
	FSM_ERROR_STATE_REACHED,
   /**  The current state changed into a non-final state */
	FSM_STATE_CHANGED,
   /**
    *  The state changed back to itself
    *
    * The state can return to itself either directly or indirectly.
    * An indirect path may include a transition from a parent state and the use of #entry_state
    */
	FSM_STATE_LOOP_SELF,
   /**
    *  The current state did not change on the given event
    *
    * If any event passed to the machine should result in a state change,
    * 	this return value should be considered as an error.
    */
	FSM_NO_STATE_CHANGE,
   /**  A final state (any but the error state) was reached */
	FSM_FINAL_STATE_REACHED,

	/** current_state of #fsm is #incl_state */
	FSM_INCONCLUSIVE_STATE_REACHED
};

/**
 *  Pass an event to the machine
 *
 * The event will be passed to the current state, and possibly to the current
 * state's parent states (if any). If the event triggers a transition, a new
 * state will be entered. If the transition has an action defined,
 * it will be called. If the transition is to a state other
 * than the current state, the current state's exit_action
 * is called (if defined). Likewise, if the state is a new
 * state, the new state's "entry action" is called (if defined).
 *
 * The returned value is negative if an error occurs.
 *
 * - Input:
 * 	+ fsm_struct the state machine to pass an event to.
 * 	+ event the event to be handled.
 *	- Return:
 * 	+ fsm_handle_event_value
 */
enum fsm_handle_event_value fsm_handle_event( fsm_t *fsm, uint16_t transition_index, message_t *message_data, void *event_data, fsm_t **new_fsm );

/**
 *  Get the current state
 *
 *	- Input:
 * 	+ fsm_struct the state machine to get the current state from.
 *	- Return:
 *		+ a pointer to the current state, otherwise, NULL if fsm is NULL.
 */
const fsm_state_t *fsm_get_current_state( const fsm_t *fsm );

/**
 *  Get the previous state
 *
 *	- Input:
 * 	+ the state machine to get the previous state from.
 * - Return:
 * 	+ the previous state, otherwise, NULL if #fsm is NULL
 * 		or if there has not yet been any transitions.
 */
const fsm_state_t *fsm_get_previous_state( const fsm_t *fsm );

/**
 *  Check if the state machine has stopped
 *
 * - Input:
 *		+ the state machine to test.
 *	- Return:
 *		+ true if the state machine is at a state having no outgoing transition,
 *			otherwise, false
 */
bool fsm_is_stopped( const fsm_t *fsm );

/**
 * Free the machine created by #fsm_init function
 *
 * - Input:
 *		+ the state machine to free.
 */
void fsm_free( fsm_t *fsm );

/**
 * Clone the machine and its current state
 *
 * - Input:
 *		+ the state machine to clone.
 */
fsm_t * fsm_clone( const fsm_t *fsm );

/**
 * Get id of the machine
 */
uint16_t fsm_get_id( const fsm_t *fsm );

/**
 * Set id of the machine
 */
void fsm_set_id( fsm_t *fsm, uint16_t id );

/**
 * Get the current execution trace of the machine
 *
 * - Input:
 *		+ the state machine to get.
 *	- Return:
 *		+ a map of events and its data. Each element of the map is indexed by event_id
 *		  of the machine, and its data has type #message_t that validates the event.
 */
const mmt_map_t* fsm_get_execution_trace( const fsm_t *fsm );

/**
 * Get data of an event_id
 */
const void *fsm_get_history( const fsm_t *fsm, uint32_t event_id );

/**
 * Free a #fsm_event_t object
 */
static inline void fsm_free_event( fsm_event_t *event, bool free_data ){
	if( event == NULL ) return;
	if( free_data == YES )
		mmt_free_and_assign_to_null( event->data );
	mmt_mem_free( event );
}

#endif /* SRC_LIB_FSM_H_ */
