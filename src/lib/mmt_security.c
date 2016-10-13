/*
 * mmt_security.c
 *
 *  Created on: Oct 10, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "mmt_security.h"
#include "mmt_alloc.h"
#include "mmt_log.h"
#include "mmt_fsm.h"
#include "plugins_engine.h"

size_t mmt_sec_get_rules_info( const rule_info_t ***rules_array ){
	return load_plugins( rules_array );
}

typedef struct _mmt_sec_handler_struct{
	size_t rules_count;
	const rule_info_t **rules_array;
	//this is called each time we reach final/error state
	mmt_sec_callback callback;
	//a parameter will give to the #callback
	void *user_data_for_callback;

	fsm_t **fsm_array;
}_mmt_sec_handler_t;

/**
 * Public API
 */
mmt_sec_handler_t *mmt_sec_register( const rule_info_t **rules_array, size_t rules_count,
		mmt_sec_callback callback, void *user_data){
	size_t i;

	_mmt_sec_handler_t *handler = mmt_malloc( sizeof( _mmt_sec_handler_t ));
	handler->rules_count = rules_count;
	handler->rules_array = rules_array;
	handler->callback = callback;
	handler->user_data_for_callback = user_data;
	//one fsm for one rule
	handler->fsm_array = mmt_malloc( sizeof( void *) * rules_count );
	for( i=0; i<rules_count; i++ )
		handler->fsm_array[i] = rules_array[i]->create_instance();
	return (mmt_sec_handler_t *)handler;
}

/**
 * Public API
 */
void mmt_sec_unregister( mmt_sec_handler_t *handler ){
	size_t i;
	if( handler == NULL ) return;
	_mmt_sec_handler_t *_handler = (_mmt_sec_handler_t *)handler;

	for( i=0; i<_handler->rules_count; i++ )
		fsm_free( _handler->fsm_array[i] );

	mmt_free( _handler->fsm_array );
	mmt_free( _handler );
}

/**
 * Public API
 */
void mmt_sec_process( const mmt_sec_handler_t *handler, const message_t *message ){
	_mmt_sec_handler_t *_handler;
	size_t i;
	enum fsm_handle_event_value val;
	fsm_t *fsm;
	const rule_info_t *rule;

	fsm_event_t event = { .type = FSM_EVENT, .data = NULL };

	mmt_assert( handler != NULL, "Need to register before processing");
	_handler = (_mmt_sec_handler_t *)handler;
	if( _handler->rules_count == 0 ) return;

	for( i=0; i<_handler->rules_count; i++){
		fsm  = _handler->fsm_array[i];
		rule = _handler->rules_array[i];

		mmt_debug( "VERIFYING RULE %d", _handler->rules_array[i]->id );
		event.data = rule->convert_message( message );
		val = fsm_handle_event( fsm, &event );

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
			break;
		//the rule is not validated
		case FSM_ERROR_STATE_REACHED:
			break;
		default: //avoid warning of compiler
			break;
		}

		mmt_free( event.data );
		mmt_debug( "Ret = %d", val );
		break;
	}
}


