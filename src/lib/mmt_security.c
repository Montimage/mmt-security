/*
 * mmt_security.c
 *
 *  Created on: Oct 10, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "mmt_security.h"
#include "base.h"
#include "mmt_lib.h"

#include "mmt_fsm.h"
#include "plugins_engine.h"
#include "rule_verif_engine.h"
#include "expression.h"
#include "rule.h"
#include "version.h"
#include "plugin_header.h"

#include "../dpi/mmt_dpi.h"

#define MAX_INSTANCE_COUNT 1000000

const char *mmt_sec_get_version_info(){
	//define in version.h
	return MMT_SEC_VERSION;
}

size_t mmt_sec_get_rules_info( const rule_info_t ***rules_array ){
	return load_mmt_sec_rules( rules_array );
}

typedef struct _mmt_sec_handler_struct{
	size_t rules_count;
	const rule_info_t **rules_array;
	//this is called each time we reach final/error state
	mmt_sec_callback callback;
	//a parameter will give to the #callback
	void *user_data_for_callback;
	rule_engine_t **engines;

	size_t proto_atts_count;
	const proto_attribute_t **proto_atts_array;
}_mmt_sec_handler_t;

size_t mmt_sec_get_rules(  const mmt_sec_handler_t *handler, const rule_info_t ***rules_array ){
	__check_null( handler, 0 );
	_mmt_sec_handler_t *_handler = (_mmt_sec_handler_t *) handler;

	*rules_array = _handler->rules_array;
	return _handler->rules_count;
}

size_t mmt_sec_get_unique_protocol_attributes( const mmt_sec_handler_t *handler, const proto_attribute_t ***proto_atts_array ){
	__check_null( handler, 0 );

	_mmt_sec_handler_t *_handler = (_mmt_sec_handler_t *) handler;

	*proto_atts_array = _handler->proto_atts_array;
	return _handler->proto_atts_count;
}

static inline void _iterate_proto_atts( void *key, void *data, void *user_data, size_t index, size_t total ){
	void **array = user_data;
	array[ index ] = data;
	//free the key being created on line 73
	mmt_mem_free( key );
}

static inline void _get_unique_proto_attts( _mmt_sec_handler_t *_handler ){
	const rule_info_t *rule;
	size_t i, j;

	mmt_map_t *map = mmt_map_init( (void *) strcmp );
	char *string;
	const proto_attribute_t *me;

	//for each rule
	for( i=0; i<_handler->rules_count; i++ ){
		rule = _handler->rules_array[i];
		for( j=0; j<rule->proto_atts_count; j++ ){
			me = &rule->proto_atts[j];
			string = mmt_mem_alloc( strlen( me->att) + strlen( me->proto ) + 1 );
			sprintf( string, "%s.%s", me->proto, me->att );
			if( mmt_map_set_data( map, string, (void *)me, NO ) != NULL ){
				//already exist
				mmt_mem_free( string );
				continue;
			}
		}
	}

	_handler->proto_atts_count = mmt_map_count( map );
	_handler->proto_atts_array = mmt_mem_alloc( _handler->proto_atts_count * sizeof( void* ));
	mmt_map_iterate( map, _iterate_proto_atts, _handler->proto_atts_array );

	mmt_map_free( map, NO );
}

/**
 * Public API
 */
mmt_sec_handler_t *mmt_sec_register( const rule_info_t **rules_array, size_t rules_count,
		mmt_sec_callback callback, void *user_data){
	size_t i;

	__check_null( rules_array, NULL );

	_mmt_sec_handler_t *handler = mmt_mem_alloc( sizeof( _mmt_sec_handler_t ));
	handler->rules_count = rules_count;
	handler->rules_array = rules_array;
	handler->callback = callback;
	handler->user_data_for_callback = user_data;
	//one fsm for one rule
	handler->engines = mmt_mem_alloc( sizeof( void *) * rules_count );
	for( i=0; i<rules_count; i++ ){
		handler->engines[i] = rule_engine_init( rules_array[i], MAX_INSTANCE_COUNT );
	}

	_get_unique_proto_attts( handler );

	return (mmt_sec_handler_t *)handler;
}


/**
 * Public API
 */
void mmt_sec_unregister( mmt_sec_handler_t *handler ){
	size_t i;
	__check_null( handler, );

	_mmt_sec_handler_t *_handler = (_mmt_sec_handler_t *)handler;

	//free data elements of _handler
	for( i=0; i<_handler->rules_count; i++ ){
		rule_engine_free( _handler->engines[i] );
	}

	mmt_mem_free( _handler->proto_atts_array );
	mmt_mem_free( _handler->engines );
	mmt_mem_free( _handler );
}

static inline enum verdict_type _get_verdict( int rule_type, enum rule_engine_result result ){
	switch ( rule_type ) {
	case RULE_TYPE_TEST:
	case RULE_TYPE_SECURITY:
		switch( result ){
		case RULE_ENGINE_RESULT_ERROR:
			return VERDICT_NOT_RESPECTED;
		case RULE_ENGINE_RESULT_VALIDATE:
			return VERDICT_UNKNOWN; //VERDICT_RESPECTED;
		default:
			return VERDICT_UNKNOWN;
		}
		break;
	case RULE_TYPE_ATTACK:
	case RULE_TYPE_EVASION:
		switch( result ){
		case RULE_ENGINE_RESULT_ERROR:
			return VERDICT_UNKNOWN; //VERDICT_NOT_DETECTED;
		case RULE_ENGINE_RESULT_VALIDATE:
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


/**
 * Public API
 */
void _mmt_sec_process( const mmt_sec_handler_t *handler, message_t *msg ){
	_mmt_sec_handler_t *_handler;
	size_t i;
	int verdict;
	enum rule_engine_result ret = RULE_ENGINE_RESULT_UNKNOWN;
	const mmt_array_t *execution_trace;

	_handler = (_mmt_sec_handler_t *)handler;

	//for each rule
	for( i=0; i<_handler->rules_count; i++){
		//mmt_debug("verify rule %d\n", _handler->rules_array[i]->id );
		ret = rule_engine_process( _handler->engines[i], msg );

		//find a validated/invalid trace
		if( ret != RULE_ENGINE_RESULT_UNKNOWN ){
			//get execution trace
			execution_trace = rule_engine_get_valide_trace( _handler->engines[i] );
			verdict = _get_verdict( _handler->rules_array[i]->type_id, ret );

			if( verdict != VERDICT_UNKNOWN ){
				//call user-callback function
				_handler->callback(
						_handler->rules_array[i],
						verdict,
						msg->timestamp,
						msg->counter,
						execution_trace,
						_handler->user_data_for_callback );

			}
		}
	}

	free_message_t( msg );
}

void mmt_sec_process( const mmt_sec_handler_t *handler, const message_t *message ){
	__check_null( handler, );
	message_t *msg = clone_message_t( message );

	_mmt_sec_process( handler, msg );
}

#define MAX_STR_SIZE 50000

char* convert_execution_trace_to_json_string( const mmt_array_t *trace ){
	char buffer[ MAX_STR_SIZE ];
	char *string = buffer;
	size_t size, i, total_len, index;
	const message_t *msg;
	const message_element_t *me;
	char *tmp;
	constant_t expr_const;
	bool is_first;

	__check_null( trace, NULL );

	buffer[0] = '\0';



	total_len = strlen( string );
	string += total_len;

	for( index=0; index<trace->elements_count; index ++ ){
		msg = trace->data[ index ];
		if( msg == NULL ) continue;



		size = sprintf( string, "%s\"event_%zu\":{\"timestamp\":%"PRIu64".%06d,\"counter\":%"PRIu64",\"attributes\":[",
				index == 0 ? "{": " ,",
						index,
						msg->timestamp / 1000000, //timestamp: second
						(int)(msg->timestamp % 1000000), //timestamp: microsecond
						msg->counter );

		is_first = YES;
		//go into detail of a message
		for( i=0; i<msg->elements_count; i++ ){
			me = &msg->elements[i];

			if( me->data == NULL ) continue;

			//convert me->data to string
			expr_const.data = me->data;
			//data_types of mmt-dpi
			//expr_const.data_type = get_attribute_data_type( me->proto_id, me->att_id );
			//data_type of mmt-security contains only either a NUMERIC or a STRING
			//expr_const.data_type = convert_data_type( expr_const.data_type );
			expr_const.data_type = me->data_type;

			if( expr_stringify_constant( &tmp, &expr_const ) ){

				total_len += size;
				if( unlikely( total_len >= MAX_STR_SIZE )) break;

				string += size;
				size = sprintf( string, "%s{\"%s.%s\":%s}",
						(is_first? "":","),
						get_protocol_name_by_id( me->proto_id ),
						get_attribute_name_by_protocol_id_and_attribute_id( me->proto_id, me->att_id ),
						tmp);
				mmt_mem_free( tmp );
				is_first = NO;
			}
		}

		total_len += size;
		if( unlikely( total_len >= MAX_STR_SIZE )) break;

		string += size;
		sprintf( string, "]}%s", //end attributes, end event_
				index == trace->elements_count - 1? "}": ""  );
	}
	return (char *) mmt_mem_dup( buffer, strlen( buffer) );
}
