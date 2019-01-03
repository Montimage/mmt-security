/*
 * fsm.c
 *
 *  Created on: 3 oct. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */


#include "../src/lib/mmt_fsm.h"
#include "../src/lib/mmt_log.h"
#include "../src/lib/mmt_alloc.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* This simple test uses a multiple-nested state machine to test that
 * traversing parents anc children work correctly.
 *
 *     +--+         o
 *     |  v         |
 * +---|------[9]---|----------+
 * |   |            v          |
 * |   |   o      +---+   (b)  |  +---+
 * |   |   |      | 1 |<----------| 2 |<---+
 * |   |   |      +---+        |  +---+<-+ |
 * |   |   |        |(d)       |         | |
 * | +-|---|--[10]--|--------+ |         | |
 * | | |   |        v        | |      (f)| |(g)
 * | | o   |      +---+<----------+      | |
 * | |     |      | 3 |-+    | |  |(a)   | |
 * | |     |      +---+ |(e) | +--+      | |
 * | |     |            v    | |         | |
 * | | +---|----[11]-------+ +-----------+ |
 * | | |   v             o +---------------+
 * | | | +---+ (h)+---+  | | | |
 * | | | | 4 |--->| 5 |<-+ | | |  +---+
 * | | | +---+    +---+    | | |  | 6 |
 * | | |   |(j)     |      | | |  +---+
 * | | |   |        |      | | |    ^
 * | | +---|--------|------+ +------+(i)
 * | +-----|--------|--------+ |
 * +-------|-----^--|----------+           +---+
 *      ^  |     |  |                      | E |
 *      +--+     +--+                      +---+
 */

enum eventTypes{ EVENT_DUMMY };

/* Use this struct as event payload, containing both the event data (a single
 * character) and the name of the expected new state (used to ensure correct
 * behaviour).  */
typedef struct event_payload_struct{
   char data;
   const char *expectedState;
}event_payload_t;

static void entry_action( void *stateData, const fsm_event_t *event );
static void exit_action( void *stateData,  const fsm_event_t *event );
static void trans_action( void *oldStateData, const fsm_event_t *event,
      void *newStateData );
static bool guard( void *condition, const fsm_event_t *event );

static fsm_state_t s1, s2, s3, s4, s5, s6, s9, s10, s11, sE;

static fsm_state_t

s1 =
{
   .data = "1",
   .entry_action = &entry_action,
   .exit_action = &exit_action,
   .transitions = (fsm_transition_t[]) {
      { EVENT_DUMMY, (void *)(intptr_t)'d', &guard, &trans_action, &s3 },
   },
   .transitions_count = 1,
   .parent_state = &s9,
},

   s2 =
{
   .data = "2",
   .entry_action = &entry_action,
   .exit_action = &exit_action,
   .transitions = (fsm_transition_t[]) {
      { EVENT_DUMMY, (void *)(intptr_t)'b', &guard, &trans_action, &s1 },
   },
   .transitions_count = 1,
},

   s3 =
{
   .data = "3",
   .entry_action = &entry_action,
   .exit_action = &exit_action,
   .transitions = (fsm_transition_t[]) {
      { EVENT_DUMMY, (void *)(intptr_t)'e', &guard, &trans_action, &s11 },
   },
   .transitions_count = 1,
   .parent_state = &s10,
},

   s4 =
{
   .data = "4",
   .entry_action = &entry_action,
   .exit_action = &exit_action,
   .transitions = (fsm_transition_t[]) {
      { EVENT_DUMMY, (void *)(intptr_t)'h', &guard, &trans_action, &s5 },
      { EVENT_DUMMY, (void *)(intptr_t)'j', &guard, &trans_action, &s9 },
   },
   .transitions_count = 2,
   .parent_state = &s11,
},

   s5 =
{
   .data = "5",
   .entry_action = &entry_action,
   .exit_action = &exit_action,
   .transitions = (fsm_transition_t[]) {
      /* Use an conditionless transition: */
      { EVENT_DUMMY, NULL, NULL, &trans_action, &s10 },
   },
   .transitions_count = 1,
   .parent_state = &s11,
},

   s6 =
{
   .data = "6",
   .entry_action = &entry_action,
   .exit_action = &exit_action,
},

   s9 =
{
   .data = "9",
   .entry_action = &entry_action,
   .exit_action = &exit_action,
   .entry_state = &s4,
   .transitions = (fsm_transition_t[]) {
      { EVENT_DUMMY, (void *)(intptr_t)'a', &guard, &trans_action, &s3 },
   },
   .transitions_count = 1,
},

   s10 =
{
   .data = "10",
   .entry_action = &entry_action,
   .exit_action = &exit_action,
   .entry_state = &s9,
   .transitions = (fsm_transition_t[]) {
      { EVENT_DUMMY, (void *)(intptr_t)'f', &guard, &trans_action, &s2 },
      { EVENT_DUMMY, (void *)(intptr_t)'i', &guard, &trans_action, &s6 },
   },
   .transitions_count = 2,
   .parent_state = &s9,
},

   s11 =
{
   .data = "11",
   .entry_action = &entry_action,
   .exit_action = &exit_action,
   .entry_state = &s5,
   .transitions = (fsm_transition_t[]) {
      { EVENT_DUMMY, (void *)(intptr_t)'g', &guard, &trans_action, &s2 },
   },
   .transitions_count = 1,
   .parent_state = &s10,
},

   sE =
{
   .data = "ERROR",
   .entry_action = &entry_action,
};

int main(){
   fsm_t *fsm = fsm_init( &s1, &sE ), *new_fsm;
   const fsm_event_t *ev;
   size_t size;
   fsm_event_t events[] = {
      /* Create transitions, with the single character as triggering event
       * data, and the expected new state name as the following string. '*' is
       * used when the unconditional transition will be followed. */
      { EVENT_DUMMY, &( event_payload_t){ 'd', "3" } },
      { EVENT_DUMMY, &( event_payload_t){ 'e', "5" } },
      { EVENT_DUMMY, &( event_payload_t){ '*', "4" } },
      { EVENT_DUMMY, &( event_payload_t){ 'j', "4" } },
      { EVENT_DUMMY, &( event_payload_t){ 'g', "2" } },
      { EVENT_DUMMY, &( event_payload_t){ 'b', "1" } },
      { EVENT_DUMMY, &( event_payload_t){ 'd', "3" } },
      { EVENT_DUMMY, &( event_payload_t){ 'e', "5" } },
      { EVENT_DUMMY, &( event_payload_t){ 'k', "4" } },
      { EVENT_DUMMY, &( event_payload_t){ 'h', "5" } },
      { EVENT_DUMMY, &( event_payload_t){ '*', "4" } },
      { EVENT_DUMMY, &( event_payload_t){ 'f', "2" } },
      { EVENT_DUMMY, &( event_payload_t){ 'b', "1" } },
      { EVENT_DUMMY, &( event_payload_t){ 'a', "3" } },
      { EVENT_DUMMY, &( event_payload_t){ 'f', "2" } },
      { EVENT_DUMMY, &( event_payload_t){ 'b', "1" } },
      { EVENT_DUMMY, &( event_payload_t){ 'd', "3" } },
      { EVENT_DUMMY, &( event_payload_t){ 'i', "6" } },
   };

   int res;
   size_t i;

	/* Hand all but the last event to the state machine: */
	for (i = 0; i < sizeof(events) / sizeof(events[0]) - 1; ++i) {
		res = fsm_handle_event(fsm, &events[i]);

		if (res == FSM_STATE_LOOP_SELF) {
			/* Prevent segmentation faults (due to the following comparison)
			 * (loops will not be tested in the first transition): */
			if (i == 0) {
				mmt_debug("Internal error. This should not happen.\n" );
				fsm_free(fsm);
				exit(4);
			}

			/* Ensure that the reported state loop is indeed a state loop (check
			 * that the expected state is the same as the previous expected
			 * state): */
			if (!strcmp(
					((event_payload_t *) events[i].data)->expectedState,
					((event_payload_t *) events[i - 1].data)->expectedState) )
				mmt_debug("State changed back to itself");
			else {
				mmt_debug("State unexpectedly changed back to itself" );
				fsm_free(fsm);
				exit(5);
			}
		}
		/* Apart from an occasional state loop, all other events handed to the
		 * state machine should result in 'fsm_stateChanged': */
		else if (res != FSM_STATE_CHANGED) {
			mmt_debug( "Unexpected return value from fsm_handle_event:"
					" %d\n", res);
			fsm_free(fsm);
			exit(2);
		}
	}

	/* The last state change is expected to result in a transition to a final
	 * state: */
	res = fsm_handle_event(fsm, &events[i]);
	if (res != FSM_FINAL_STATE_REACHED) {
		mmt_debug( "Unexpected return value from fsm_handle_event: %d\n", res);
		fsm_free(fsm);
		exit(3);
	}

	size = fsm_get_current_execution_trace( fsm, &ev );
	for( i=0; i<size; i++ )
		mmt_debug(" trace %zu: %s ", i, ((event_payload_t *) ev[i].data)->expectedState );

	mmt_debug("A final state was reached (as expected)");
	fsm_free(fsm);

   return 0;
}

static void entry_action(void *stateData, const fsm_event_t *event) {
	mmt_debug("Entering %s\n", (const char *) stateData);
}

static void exit_action(void *stateData, const fsm_event_t *event) {
	mmt_debug("Exiting %s\n", (const char *) stateData);
}

static void trans_action(void *oldStateData, const fsm_event_t *event,
		void *newStateData) {
	struct event_payload_struct *eventData =
			(struct event_payload_struct *) event->data;

	mmt_debug("Event '%c'\n", eventData->data);

	if (strcmp(((const char *) newStateData), eventData->expectedState)) {
		mmt_debug("Unexpected state transition (to %s)\n",
				(const char *) newStateData);
		exit(1);
	}
}

static bool guard(void *condition, const fsm_event_t *event) {
	struct event_payload_struct *eventData =
			(struct event_payload_struct *) event->data;

	return (intptr_t) condition == (intptr_t) eventData->data;
}
