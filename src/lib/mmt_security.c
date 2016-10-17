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
#include "rule_verif_engine.h"

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
	rule_engine_t **engines;
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
	handler->engines = mmt_malloc( sizeof( void *) * rules_count );
	for( i=0; i<rules_count; i++ ){
		handler->engines[i] = rule_engine_init( rules_array[i], 1000 );
	}
	return (mmt_sec_handler_t *)handler;
}


/**
 * Public API
 */
void mmt_sec_unregister( mmt_sec_handler_t *handler ){
	size_t i;
	if( handler == NULL ) return;
	_mmt_sec_handler_t *_handler = (_mmt_sec_handler_t *)handler;

	//free data elements of _handler
	for( i=0; i<_handler->rules_count; i++ ){
		rule_engine_free( _handler->engines[i] );
	}

	mmt_free( _handler->engines );
	mmt_free( _handler );
}

/**
 * Public API
 */
void mmt_sec_process( const mmt_sec_handler_t *handler, const message_t *message ){
	_mmt_sec_handler_t *_handler;
	size_t i;

	mmt_assert( handler != NULL, "Need to register before processing");
	_handler = (_mmt_sec_handler_t *)handler;
	if( _handler->rules_count == 0 ) return;

	//for each rule
	for( i=0; i<_handler->rules_count; i++){
		rule_engine_process( _handler->engines[i], message );
		//break;
	}
}

#define MAX_STRING_SIZE 2000

static void _iterate_to_get_string( void *key, void *data, void *u_data, size_t index, size_t total){
	char *string = (char *) u_data;
	size_t size, i;
	size = sprintf( string, "{event_id : %d", *(uint16_t *) key );
	string += size;
	sprintf( string, "}" );
}

char* convert_execution_trace_to_json_string( const mmt_map_t *trace ){
	char buffer[ MAX_STRING_SIZE ];
	size_t index = 0;

	mmt_map_iterate( trace, _iterate_to_get_string, &buffer[ index ] );

	return (char *) mmt_mem_dup( buffer, index );
}
