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

size_t mmt_sec_filter_rules( const char *rule_mask, size_t rules_count, const rule_info_t **rules_array ){
	uint32_t *rule_range, rule_id;
	int i, j, k, rules_count_per_thread;

	//Rules to be disabled
	if( rule_mask == NULL || strlen( rule_mask) == 0 )
		return rules_count;

	//rules are not verified
	rules_count_per_thread = get_special_rules_for_thread( 0, rule_mask, &rule_range );
	if( rules_count_per_thread > 0 ){
		//move ignored rules to the end
		//rule_ptr will ignored the last n rules
		for( j=rules_count_per_thread-1; j>=0; j-- ){
			rule_id = rule_range[ j ];
			if( rules_count == 0 )
				return rules_count;

			for( k=rules_count-1; k>=0; k-- )
				if( rule_id == rules_array[k]->id ){
					//ignore this rule: rules_array[rules_count--]
					rules_count --;

					rules_array[k] = rules_array[ rules_count ];;
					break;
				}
		}
	}
	mmt_mem_free( rule_range );
	return rules_count;
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
	size_t *alerts_count;

	//TODO: this limits 64 events per mmt_security, i.e., set of rules processed
	//by this handler have maximally 64 events
	uint64_t *rules_hash; //a 64-bit hash number of each rule

	bool verbose;
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
	//free the key being created on line 99
	mmt_mem_free( key );
}

static inline void _get_unique_proto_attts( _mmt_sec_handler_t *_handler ){
	const rule_info_t *rule;
	size_t i, j;

	mmt_map_t *map = mmt_map_init( (void *) strcmp );
	char *proto_att_key;
	const proto_attribute_t *me, *old;

	//for each rule
	for( i=0; i<_handler->rules_count; i++ ){
		rule = _handler->rules_array[i];
		for( j=0; j<rule->proto_atts_count; j++ ){
			me = &rule->proto_atts[j];
			proto_att_key  = mmt_mem_alloc( 10 );
			sprintf( proto_att_key, "%d.%d",  me->proto_id, me->att_id );

			if( (old = mmt_map_set_data( map, proto_att_key, (void *)me, NO )) != NULL ){
				//already exist
				mmt_mem_free( proto_att_key );
				continue;
			}
		}
	}

	_handler->proto_atts_count = mmt_map_count( map );
	if( _handler->proto_atts_count > 64 )
		mmt_halt( "A single mmt_security cannot handler more than 64 different proto.att. You might need to use mmt_smp_sec to divide work load." );

	_handler->proto_atts_array = mmt_mem_alloc( _handler->proto_atts_count * sizeof( void* ));
	mmt_map_iterate( map, _iterate_proto_atts, _handler->proto_atts_array );

	mmt_map_free( map, NO );
}


static inline uint64_t _calculate_hash_number_of_a_rule( size_t rule_index, const _mmt_sec_handler_t * handler ){
	const rule_info_t *rule = handler->rules_array[ rule_index ];
	size_t j, k;
	const proto_attribute_t *me;
	uint64_t  hash = 0;

	//for each proto_att of this rules
	for( j=0; j<rule->proto_atts_count; j++ ){
		me = &rule->proto_atts[ j ];
		for( k=0; k < handler->proto_atts_count; k++ )
			if( handler->proto_atts_array[k]->proto_id == me->proto_id  &&
					handler->proto_atts_array[k]->att_id == me->att_id  ){

				//this rule need proto_att in k-th of handler->proto_atts_array
				BIT_SET( hash, k );
			}
	}

	if( unlikely( hash == 0 ) )
		mmt_warn( "Rule %"PRIu32" does not concerns to any protocol (%s)", rule->id, rule->description );

	return hash;
}

/**
 * Public API
 */
mmt_sec_handler_t *mmt_sec_register( const rule_info_t **rules_array, size_t rules_count, bool verbose,
		mmt_sec_callback callback, void *user_data){
	size_t i;
	uint32_t max_instance_count = get_config()->security.max_instances;
	__check_null( rules_array, NULL );

	_mmt_sec_handler_t *handler = mmt_mem_alloc( sizeof( _mmt_sec_handler_t ));
	handler->rules_count = rules_count;
	handler->rules_array = rules_array;
	handler->callback    = callback;
	handler->user_data_for_callback = user_data;
	handler->alerts_count = mmt_mem_alloc( sizeof (size_t ) * rules_count );
	handler->verbose     = verbose;
	//one fsm for one rule
	handler->engines = mmt_mem_alloc( sizeof( void *) * rules_count );
	for( i=0; i<rules_count; i++ ){
		handler->engines[i]      = rule_engine_init( rules_array[i], max_instance_count );
		handler->alerts_count[i] = 0;
	}

	//printf(" Thread pid=%2d processes %4zu rules: ", gettid(), rules_count );

	_get_unique_proto_attts( handler );

	handler->rules_hash = mmt_mem_alloc( sizeof( uint64_t ) * rules_count );
	for( i=0; i<rules_count; i++ ){
		handler->rules_hash[ i ] = _calculate_hash_number_of_a_rule( i, handler );
	}

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

	for( i=0; i<_handler->rules_count; i++ ){
		if( _handler->alerts_count[ i ] == 0 )
			continue;

		if( _handler->verbose )
			printf(" - rule %"PRIu32" generated %"PRIu64" verdicts\n", _handler->rules_array[i]->id, _handler->alerts_count[ i ] );
		alerts_count += _handler->alerts_count[ i ];
	}

	//free data elements of _handler
	for( i=0; i<_handler->rules_count; i++ )
		rule_engine_free( _handler->engines[i] );

	mmt_mem_free( _handler->proto_atts_array );
	mmt_mem_free( _handler->engines );
	mmt_mem_free( _handler->rules_hash );
	mmt_mem_free( _handler->alerts_count );
	mmt_mem_free( _handler );

	return alerts_count;
}

static inline uint64_t _calculate_hash_number_of_input_message( const message_t *msg, const _mmt_sec_handler_t *_handler ){
	uint64_t hash = 0;
	size_t i;

	for( i=0; i < _handler->proto_atts_count; i++ )
		if( get_element_data_message_t( msg, _handler->proto_atts_array[ i ]->proto_id, _handler->proto_atts_array[ i ]->att_id ) != NULL )
			BIT_SET( hash, i );

	return hash;
}
/**
 * Public API (used by mmt_sec_smp)
 */
void mmt_sec_process( const mmt_sec_handler_t *handler, message_t *msg ){
#ifdef DEBUG_MODE
	mmt_assert( handler != NULL, "msg cannot be null");
	mmt_assert( msg != NULL, "msg cannot be null");
#endif

	size_t i;
	int verdict;
	const mmt_array_t *execution_trace;

	_mmt_sec_handler_t *_handler = (_mmt_sec_handler_t *)handler;
	uint64_t hash = _calculate_hash_number_of_input_message( msg, _handler );

#ifdef DEBUG_MODE
	_handler->messages_count ++;
#endif

	//for each rule
	for( i=0; i<_handler->rules_count; i++){
		//msg does not contain enough proto.att for i-th rule
		if( (hash | _handler->rules_hash[i]) != hash )
			continue;

//		continue;

//		mmt_debug("verify rule %d\n", _handler->rules_array[i]->id );
		verdict = rule_engine_process( _handler->engines[i], msg );

		//found a validated/invalid trace
		if( verdict != VERDICT_UNKNOWN ){
			_handler->alerts_count[i] ++;

			if( _handler->callback != NULL ){
				//get execution trace
				execution_trace = rule_engine_get_valide_trace( _handler->engines[i] );

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
		default:
			//non printable
			if( *tmp < 32 )
				*tmp = '.';
		}


		tmp ++;
		len --;
	}

}

#define MAX_STR_SIZE 10000

static const char* _convert_execution_trace_to_json_string( const mmt_array_t *trace, const rule_info_t *rule ){
	static __thread_scope char buffer[ MAX_STR_SIZE + 1 ];
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
				//ARP
				case 30:
					switch ( pro_ptr->att_id ){
					case 7:   //AR_SIP
					case 9:   //AR_TIP
						u8_ptr = (uint8_t *) me->data;
						size   = sprintf(str_ptr, "\"%d.%d.%d.%d\"",
								u8_ptr[0], u8_ptr[1], u8_ptr[2], u8_ptr[3] );
					}

					break;
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
				//

			}//end of switch( me->data_type )

			//close } here
			str_ptr += size;
			*str_ptr = '}';
			*(str_ptr + 1 ) = '\0';

			size = 1;

			is_first = NO;
		}

		total_len -= size;
		if( unlikely( total_len <= 0 )) break;

		str_ptr += size;
		str_ptr += snprintf( str_ptr, total_len, "]}%s", //end attributes, end event_
				(index == trace->elements_count - 1)? "}": ""  );
	}

	return buffer;
}


const char* mmt_convert_execution_trace_to_json_string( const mmt_array_t *trace, const rule_info_t *rule ){
	return _convert_execution_trace_to_json_string( trace, rule );
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
void mmt_sec_print_verdict(
		const rule_info_t *rule,		//id of rule
		enum verdict_type verdict,
		uint64_t timestamp,  //moment the rule is validated
		uint64_t counter,
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

	len = snprintf( message, MAX_MSG_SIZE, "10,0,\"eth0\",%ld,%"PRIu32",%"PRIu32",\"%s\",\"%s\",\"%s\", %s",
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
	struct tm tm;
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
			printf("\n\t- event %-2zu        ", j+1 );
			//visite each proto/att of one event
			proto_atts = &(rules_arr[i]->proto_atts_events[ j+1 ]);
			for( k=0; k<proto_atts->elements_count; k++ ){
				proto = proto_atts->data[k];
				printf("%c %s.%s (%d.%d)", k==0?':':',', proto->proto, proto->att,
						 proto->proto_id, proto->att_id );

				//add to unique set
				sprintf( tmp_string, "%s.%s", proto->proto, proto->att );
				if( strstr( string, tmp_string ) == NULL )
					ch_ptr += sprintf( ch_ptr, "\"%s.%s\",", proto->proto, proto->att );
			}
		}

		tm = *localtime(& rules_arr[i]->version.created_date );
		printf("\n\t- version         : %s (%s - %d-%d-%d %d:%d:%d), dpi version %s",
				 rules_arr[i]->version.number,
				 rules_arr[i]->version.hash,
				 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
				 rules_arr[i]->version.dpi );
	}

	//remove the last comma
	size = strlen( string );
	if( size > 0 ) string[ size - 1 ] = '\0';

	printf("\n\nProtocols and their attributes used in these rules:\n\t %s\n\n", string );

	mmt_mem_free( rules_arr );
	unload_mmt_sec_rules();
}
