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

typedef struct _mmt_sec_handler_struct{
	size_t rules_count;
	const size_t *rules_id_array;
	//this is called each time we reach final/error state
	mmt_sec_callback callback;
	//a parameter will give to the #callback
	void *user_data_for_callback;

	fsm_t *fsm_array;
}_mmt_sec_handler_t;

mmt_sec_handler_t *mmt_sec_register_rules( const size_t *rules_id_array, size_t rules_count,
		mmt_sec_callback callback, void *user_data){
	_mmt_sec_handler_t *handler = mmt_malloc( sizeof( _mmt_sec_handler_t ));
	handler->rules_count = rules_count;
	handler->rules_id_array = rules_id_array;
	handler->callback = callback;
	handler->user_data_for_callback = user_data;
	handler->fsm_array = NULL;
	return handler;
}

void mmt_sec_process( const mmt_sec_handler_t *handler, const message_t *message ){
	_mmt_sec_handler_t *_handler;
	mmt_assert( handler != NULL, "Need to register before processing");
	_handler = (_mmt_sec_handler_t *)handler;
}
