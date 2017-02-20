/*
 * mmt_security.c
 *
 *  Created on: Oct 10, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <math.h>

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

#include "../dpi/types_defs.h"
#include "../dpi/mmt_dpi.h"

//string size of an alert in JSON format
#define MAX_MSG_SIZE 10000

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

	//number of generated alerts
	size_t alerts_count;

#ifdef DEBUG_MODE
	size_t messages_count;
#endif
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
	//free the key being created on line 97
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
	uint32_t max_instance_count = get_config()->security.max_instances;
	__check_null( rules_array, NULL );

	_mmt_sec_handler_t *handler = mmt_mem_alloc( sizeof( _mmt_sec_handler_t ));
	handler->rules_count = rules_count;
	handler->rules_array = rules_array;
	handler->callback    = callback;
	handler->user_data_for_callback = user_data;
	handler->alerts_count = 0;
	//one fsm for one rule
	handler->engines = mmt_mem_alloc( sizeof( void *) * rules_count );
	for( i=0; i<rules_count; i++ )
		handler->engines[i] = rule_engine_init( rules_array[i], max_instance_count );

#ifdef DEBUG_MODE
//	printf(" Thread pid=%2d processes %4zu rules: ", gettid(), rules_count );
//	for( i=0; i<rules_count; i++ )
//		printf("%"PRIu32"%c", rules_array[i]->id, i == rules_count -1 ? '\n':',' );
#endif

	_get_unique_proto_attts( handler );

#ifdef DEBUG_MODE
	handler->messages_count = 0;
#endif

	return (mmt_sec_handler_t *)handler;
}


/**
 * Public API
 */
size_t mmt_sec_unregister( mmt_sec_handler_t *handler ){
	size_t i, alerts_count = 0;
	__check_null( handler, 0);

	_mmt_sec_handler_t *_handler = (_mmt_sec_handler_t *)handler;

	alerts_count = _handler->alerts_count;

#ifdef DEBUG_MODE
	mmt_debug("received %zu messages and generated %zu alerts",
			_handler->messages_count, _handler->alerts_count );
#endif

	//free data elements of _handler
	for( i=0; i<_handler->rules_count; i++ )
		rule_engine_free( _handler->engines[i] );

	mmt_mem_free( _handler->proto_atts_array );
	mmt_mem_free( _handler->engines );
	mmt_mem_free( _handler );

	return alerts_count;
}

/**
 * Public API (used by mmt_sec_smp)
 */
void mmt_sec_process( const mmt_sec_handler_t *handler, message_t *msg ){
#ifdef DEBUG_MODE
	mmt_assert( handler != NULL, "msg cannot be null");
	mmt_assert( msg != NULL, "msg cannot be null");
#endif
	_mmt_sec_handler_t *_handler;
	size_t i;
	int verdict;
	const mmt_array_t *execution_trace;

	_handler = (_mmt_sec_handler_t *)handler;

#ifdef DEBUG_MODE
	_handler->messages_count ++;
#endif

	//for each rule
	for( i=0; i<_handler->rules_count; i++){
		//mmt_debug("verify rule %d\n", _handler->rules_array[i]->id );
		verdict = rule_engine_process( _handler->engines[i], msg );

		//find a validated/invalid trace
		if( verdict != VERDICT_UNKNOWN ){
			_handler->alerts_count ++;

			//TODO: HN removes this (this is for testing only)
							mmt_sec_print_verdict(
								_handler->rules_array[i],
								verdict,
								0,
								0,
								NULL,
								NULL );

//			if( _handler->callback != NULL ){
//				//get execution trace
//				execution_trace = rule_engine_get_valide_trace( _handler->engines[i] );
//
//				//call user-callback function
//				_handler->callback(
//					_handler->rules_array[i],
//					verdict,
//					msg->timestamp,
//					msg->counter,
//					execution_trace,
//					_handler->user_data_for_callback );
//			}
		}
	}
	free_message_t( msg );
}

static inline void _remove_special_character( char * tmp, size_t len ){
	while( len != 0 ){
		switch( *tmp ){
		case '\b': //  Backspace (ascii code 08)
		case '\f': //  Form feed (ascii code 0C)
		case '\n': //  New line
		case '\r': //  Carriage return
		case '\t': //  Tab
		case '\"': //  Double quote
		case '\\': //  Backslash character
		case '\0':
		//case '\u': //  unicode
			*tmp = '.';
			break;
		}

		tmp ++;
		len --;
	}

}

#define MAX_STR_SIZE 10000

static const char* _convert_execution_trace_to_json_string( const mmt_array_t *trace, const rule_info_t *rule ){
	static __t_scope char buffer[ MAX_STR_SIZE + 1 ];
	char *str_ptr, *c_ptr;
	size_t size, i, j, total_len, index;
	const message_t *msg;
	const message_element_t *me;
	bool is_first;
	struct timeval time;
	const mmt_array_t *proto_atts_event; //proto_att of an event
	const proto_attribute_t *pro_ptr;
	double double_val;
	uint8_t *u8_ptr;

	__check_null( trace, NULL );

	buffer[0] = '\0';

	//number of elements in traces <= number of real events + timeout event
	mmt_assert( trace->elements_count <= rule->events_count + 1,
			"Impossible: elements_count > events_count (%zu > %d + 1)", trace->elements_count, rule->events_count);

	total_len = MAX_STR_SIZE;
	str_ptr   = buffer;

	for( index=0; index<trace->elements_count; index ++ ){
		msg = trace->data[ index ];
		if( msg == NULL ) continue;

		mmt_sec_decode_timeval( msg->timestamp, &time );

		size = snprintf( str_ptr, total_len, "%c\"event_%zu\":{\"timestamp\":%"PRIu64".%06lu,\"counter\":%"PRIu64",\"attributes\":[",
						total_len == MAX_STR_SIZE ? '{': ',',
						index,
						time.tv_sec, //timestamp: second
						time.tv_usec, //timestamp: microsecond
						msg->counter );

		is_first = YES;

		//get array of proto_att used in the event having #index
		proto_atts_event = &rule->proto_atts_events[ index ];

		//go into detail of a message
		for( i=0; i<msg->elements_count; i++ ){
			me = &msg->elements[i];

			if( me->data == NULL ) continue;

			//check if #me is used in this event of the rule #rule
			for( j=0; j<proto_atts_event->elements_count; j++ ){
				pro_ptr = (proto_attribute_t *)proto_atts_event->data[ j ];
				if( pro_ptr->att_id == me->att_id && pro_ptr->proto_id == me->proto_id )
					break;
			}

			//not found any variable/proto_att in this event using "me"
			if( j>= proto_atts_event->elements_count )
				continue;

			total_len -= size;
			if( unlikely( total_len <= 0 )) break;

			str_ptr += size;

			//pro_ptr->data_type;
			switch( me->data_type ){
			case NUMERIC:
				double_val = *(double *)me->data;

				//do not forget }
				size = snprintf( str_ptr, total_len, "%s{\"%s.%s\":%.2f",
							(is_first? "":","),
							pro_ptr->proto,
							pro_ptr->att,
							double_val );

				c_ptr = str_ptr + size;
				//remove zero at the end, e.g., 10.00 ==> 10
				while( *c_ptr == '0' || *c_ptr == '\0' ){
					c_ptr --;
					size --;

					if( *c_ptr == '.'){
						//size --;
						break;
					}
				}

				break;

			default:
				//do not forget }
				size = snprintf( str_ptr, total_len, "%s{\"%s.%s\":",
						(is_first? "":","),
						pro_ptr->proto,
						pro_ptr->att);

				str_ptr   += size;
				total_len -= size;

				u8_ptr = NULL;

				switch( pro_ptr->proto_id ){
				//IP SRC = 12, DEST = 13
				case 178:
					switch ( pro_ptr->att_id ){
					case 12:
					case 13:
						u8_ptr = (uint8_t *) me->data;
						size   = sprintf(str_ptr, "\"%d.%d.%d.%d\"",
								u8_ptr[0], u8_ptr[1], u8_ptr[2], u8_ptr[3] );
					}

					break;

				//IPV6 SRC=7 DST=8
				case 182:
					switch( pro_ptr->att_id ){
					case 7:
					case 8:
						u8_ptr = (uint8_t *) me->data;
						size   = sprintf(str_ptr, "\"%02x:%02x:%02x:%02x:%02x:%02x\"",
								u8_ptr[0], u8_ptr[1], u8_ptr[2], u8_ptr[3], u8_ptr[4], u8_ptr[5] );
					}
					break;

				//Ethernet
				case 99:
					switch( pro_ptr->att_id ){
					case 7:
					case 8:
						u8_ptr = (uint8_t *) me->data;
						size   = sprintf(str_ptr, "\"%02x:%02x:%02x:%02x:%02x:%02x\"",
								u8_ptr[0], u8_ptr[1], u8_ptr[2], u8_ptr[3], u8_ptr[4], u8_ptr[5] );
					}
					break;

				}// end of switch( pro_ptr->proto_id ){

				//if the attribute is not neither IP nor MAC
				if( u8_ptr == NULL ){
					size = sprintf( str_ptr, "\"%s\"", (char *) me->data );
					_remove_special_character(  str_ptr + 1, size - 2 );
				}

				//close } here
				str_ptr += size;
				*str_ptr = '}';
				*(str_ptr + 1 ) = '\0';

				size = 1;
				//

			}//end of switch( me->data_type )

			is_first = NO;
		}

		total_len -= size;
		if( unlikely( total_len <= 0 )) break;

		str_ptr += size;
		snprintf( str_ptr, total_len, "]}%s", //end attributes, end event_
				(index == trace->elements_count - 1)? "}": ""  );
	}

	return buffer;
}

//TODO: hn removes this
//this is for testing only
void mmt_sec_print_verdict(
		const rule_info_t *rule,		//id of rule
		enum verdict_type verdict,
		uint64_t timestamp,  //moment the rule is validated
		uint32_t counter,
		const mmt_array_t *const trace,
		void *user_data )
{
	//TODO this limit mmt-sec on max 100 K rules
	static uint32_t  prop_index[100000] = {0}, *p;
	size_t i;
	if (unlikely (rule == NULL)){
		for( i=1; i<=counter; i++)
			printf("property %3zu generates %6"PRIu32" alerts\n", i, prop_index[ i ]);
		return;
	}

	//each rule is processed by only one thread
	//=> this is thread-safe
	p = prop_index + rule->id;
	(*p) ++;
}

/**
 * PUBLIC API
 * Print verdicts to verdict printer
 * @param rule
 * @param verdict
 * @param timestamp
 * @param counter
 * @param trace
 * @param user_data
 */
void _mmt_sec_print_verdict(
		const rule_info_t *rule,		//id of rule
		enum verdict_type verdict,
		uint64_t timestamp,  //moment the rule is validated
		uint32_t counter,
		const mmt_array_t *const trace,
		void *user_data )
{
	int len;
	char message[ MAX_MSG_SIZE + 1 ];
	const char *description = "";
	const char *string = _convert_execution_trace_to_json_string( trace, rule );
	static uint32_t alert_index = 0;
	//TODO this limit mmt-sec on max 100 K rules
	static uint8_t  prop_index[100000] = {0}, *p;

	__sync_add_and_fetch( &alert_index, 1 );


	//each rule is processed by only one thread
	//=> this is thread-safe
	p = prop_index + rule->id - 1;
	(*p) ++;

	switch (*p){
	case 1:
		description = rule->description;
		break;
		//print description of a rule each 1O alerts
	case 10:
		//reset counter
		(*p) = 0;
		break;
	}

	len = snprintf( message, MAX_MSG_SIZE, "10,0,\"eth0\",%ld,%"PRIu32",%"PRIu32",\"%s\",\"%s\",\"%s\", {%s}",
			time( NULL ),
			alert_index, //index of alarm
			rule->id,
			verdict_type_string[verdict],
			rule->type_string,
			description,
			string );

	message[ len ] = '\0';
	verdict_printer_send( message );
}

/**
 * PUBLIC API
 * Print information of available rules
 */
void mmt_sec_print_rules_info(){
	const rule_info_t **rules_arr;
	size_t i, j, k, n  = 0, size;
	const mmt_array_t *proto_atts;
	const proto_attribute_t *proto;

	char string[ 100000 ], *ch_ptr, tmp_string[ 1000 ];
	string[ 0 ] = '\0';
	ch_ptr = &string[ 0 ];

	n = load_mmt_sec_rules( &rules_arr );

	printf("Found %zu rule%s", n, n<=1? ".": "s." );

	for( i=0; i<n; i++ ){
		printf("\n%zu - Rule id: %d", (i+1), rules_arr[i]->id );
		printf("\n\t- type            : %s",  rules_arr[i]->type_string );
		printf("\n\t- description     : %s",  rules_arr[i]->description );
		printf("\n\t- if_satisfied    : %s",  rules_arr[i]->if_satisfied );
		printf("\n\t- if_not_satisfied: %s",  rules_arr[i]->if_not_satisfied );
		//for each event
		for(j=0; j<rules_arr[i]->events_count; j++ ){
			printf("\n\t- event %2zu        ", j+1 );
			//visite each proto/att of one event
			proto_atts = &(rules_arr[i]->proto_atts_events[ j+1 ]);
			for( k=0; k<proto_atts->elements_count; k++ ){
				proto = proto_atts->data[k];
				printf("%c %s.%s", k==0?':':',', proto->proto, proto->att );

				//add to unique set
				sprintf( tmp_string, "%s.%s", proto->proto, proto->att );
				if( strstr( string, tmp_string ) == NULL )
					ch_ptr += sprintf( ch_ptr, "\"%s.%s\",", proto->proto, proto->att );
			}
		}
	}

	//remove the last comma
	size = strlen( string );
	if( size > 0 ) string[ size - 1 ] = '\0';

	printf("\n\nProtocols and their attributes used in these rules:\n\t %s\n\n", string );

	mmt_mem_free( rules_arr );
	unload_mmt_sec_rules();
}

/**
 * Public API
 * Convert data in format of MMT-Probe to data in format of MMT-Sec
 */
int mmt_sec_convert_data( const void *data, int type, void **new_data, int *new_type ){
	double number = 0;

	uint16_t size;
	char *new_string;

	//does not exist data for this proto_id and att_id
	__check_null( data, 1 );

	switch( type ){
	case MMT_UNDEFINED_TYPE: /**< no type constant value */
		break;
	case MMT_DATA_CHAR: /**< 1 character constant value */
		number = *(char *) data;
		*new_type = NUMERIC;
		*new_data = mmt_mem_force_dup( &number, sizeof( number ));
		return 0;

	case MMT_U8_DATA: /**< unsigned 1-byte constant value */
		number = *(uint8_t *) data;
		*new_type = NUMERIC;
		*new_data = mmt_mem_force_dup( &number, sizeof( number ));
		return 0;

	case MMT_DATA_PORT: /**< tcp/udp port constant value */
	case MMT_U16_DATA: /**< unsigned 2-bytes constant value */
		number = *(uint16_t *) data;
		*new_type = NUMERIC;
		*new_data = mmt_mem_force_dup( &number, sizeof( number ));
		return 0;

	case MMT_U32_DATA: /**< unsigned 4-bytes constant value */
		number = *(uint32_t *) data;
		*new_type = NUMERIC;
		*new_data = mmt_mem_force_dup( &number, sizeof( number ));
		return 0;

	case MMT_U64_DATA: /**< unsigned 8-bytes constant value */
		number = *(uint64_t *) data;
		*new_type = NUMERIC;
		*new_data = mmt_mem_force_dup( &number, sizeof( number ));
		return 0;

	case MMT_DATA_FLOAT: /**< float constant value */
		number = *(float *) data;
		*new_type = NUMERIC;
		*new_data = mmt_mem_force_dup( &number, sizeof( number ));
		return 0;

	case MMT_DATA_MAC_ADDR: /**< ethernet mac address constant value */
		*new_type = STRING;
		*new_data = mmt_mem_force_dup( data, 6 );
		return 0;

	case MMT_DATA_IP_ADDR: /**< ip address constant value */
		*new_type = STRING;
		*new_data = mmt_mem_force_dup( data, 4 );
		return 0;

	case MMT_DATA_IP6_ADDR: /**< ip6 address constant value */
		*new_type = STRING;
		*new_data = mmt_mem_force_dup( data, 6 );
		return 0;

	case MMT_DATA_POINTER: /**< pointer constant value (size is void *) */
	case MMT_DATA_PATH: /**< protocol path constant value */
	case MMT_DATA_TIMEVAL: /**< number of seconds and microseconds constant value */
	case MMT_DATA_BUFFER: /**< binary buffer content */
	case MMT_DATA_POINT: /**< point constant value */
	case MMT_DATA_PORT_RANGE: /**< tcp/udp port range constant value */
	case MMT_DATA_DATE: /**< date constant value */
	case MMT_DATA_TIMEARG: /**< time argument constant value */
	case MMT_DATA_STRING_INDEX: /**< string index constant value (an association between a string and an integer) */
	case MMT_DATA_IP_NET: /**< ip network address constant value */
	case MMT_DATA_LAYERID: /**< Layer ID value */
	case MMT_DATA_FILTER_STATE: /**< (filter_id: filter_state) */
	case MMT_DATA_PARENT: /**< (filter_id: filter_state) */
	case MMT_STATS: /**< pointer to MMT Protocol statistics */
		break;

	case MMT_BINARY_DATA: /**< binary constant value */
	case MMT_BINARY_VAR_DATA: /**< binary constant value with variable size given by function getExtractionDataSizeByProtocolAndFieldIds */
	case MMT_STRING_DATA: /**< text string data constant value. Len plus data. Data is expected to be '\0' terminated and maximum BINARY_64DATA_LEN long */
	case MMT_STRING_LONG_DATA: /**< text string data constant value. Len plus data. Data is expected to be '\0' terminated and maximum STRING_DATA_LEN long */
		*new_type = STRING;
		*new_data = mmt_mem_dup( ((mmt_binary_var_data_t *)data)->data, ((mmt_binary_var_data_t *)data)->len );
		return 0;

	case MMT_HEADER_LINE: /**< string pointer value with a variable size. The string is not necessary null terminating */
		*new_type = STRING;
		*new_data = mmt_mem_dup( ((mmt_header_line_t *)data)->ptr, ((mmt_header_line_t *)data)->len );
		return 0;

	case MMT_STRING_DATA_POINTER: /**< pointer constant value (size is void *). The data pointed to is of type string with null terminating character included */
		*new_type = STRING;
		*new_data  = mmt_mem_dup( data, strlen( (char*) data) );
		return 0;

	default:
		break;
	}

	*new_type = VOID;
	*new_data = NULL;

#ifdef DEBUG_MODE
	mmt_error("Data type %d has not yet implemented", type);
#endif

	return 1;
}
