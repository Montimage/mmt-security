/*
 * security.c
 *
 *  Created on: Mar 17, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */


#include <signal.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include "mmt_security.h"
#include "mmt_lib.h"

#include "base.h"
#include "mmt_lib.h"

#include "mmt_fsm.h"
#include "plugins_engine.h"
#include "rule_verif_engine.h"
#include "expression.h"
#include "rule.h"
#include "version.h"
#include "plugin_header.h"

#include "mmt_single_security.h"
#include "mmt_smp_security.h"

static const rule_info_t **rules = NULL;
static size_t rules_count = 0;

static const proto_attribute_t **proto_atts = NULL;
static size_t proto_atts_count = 0;

static bool is_init = NO;

//string size of an alert in JSON format
#define MAX_MSG_SIZE 10000


struct mmt_sec_handler_struct{
	void *sec_handler;

	void (*process)( void *, message_t *);

	int threads_count;
};



void _filter_rules( const char *rule_mask ){
	uint32_t *rule_range, rule_id;
	int i, j, k, count;

	if( rule_mask == NULL || strlen( rule_mask ) == 0 )
		return;

	//rules are not verified
	count = expand_number_range( rule_mask, &rule_range );
	if( count > 0 ){
		//move ignored rules to the end
		//rule_ptr will ignored the last n rules
		for( j=count-1; j>=0; j-- ){
			rule_id = rule_range[ j ];
			if( rules_count == 0 )
				return;

			for( k=rules_count-1; k>=0; k-- )
				if( rule_id == rules[k]->id ){
					//ignore this rule: rules_array[rules_count--]
					rules_count --;

					rules[k] = rules[ rules_count ];;
					break;
				}
		}
	}
	mmt_mem_free( rule_range );
}

static inline void _iterate_proto_atts( void *key, void *data, void *user_data, size_t index, size_t total ){
	proto_atts[ index ] = data;
	//free the key being created on line 88 of function _get_unique_proto_attts
	mmt_mem_free( key );
}


static inline void _get_unique_proto_attts( ){
	const rule_info_t *rule;
	size_t i, j;

	mmt_map_t *map = mmt_map_init( (void *) strcmp );
	char *proto_att_key;
	const proto_attribute_t *me, *old;

	//for each rule
	for( i=0; i<rules_count; i++ ){
		rule = rules[i];
		for( j=0; j<rule->proto_atts_count; j++ ){
			me = &rule->proto_atts[j];
			proto_att_key  = mmt_mem_alloc( 12 );
			snprintf( proto_att_key, 10, "%4d.%4d",  me->proto_id, me->att_id );

			if( (old = mmt_map_set_data( map, proto_att_key, (void *)me, NO )) != NULL ){
				//already exist
				mmt_mem_free( proto_att_key );
			}
		}
	}

	proto_atts_count = mmt_map_count( map );
	//TODO: limit to 64 proto.att ???
	if( proto_atts_count > 64 )
		mmt_halt( "A single mmt_security cannot handler more than 64 different proto.att. You might need to use mmt_smp_sec to divide work load." );

	proto_atts = mmt_mem_alloc( proto_atts_count * sizeof( void* ));
	mmt_map_iterate( map, _iterate_proto_atts, NULL );

	mmt_map_free( map, NO );
}

static inline void _update_rule_hash_proto_att( ){
	int index, i, j;
	const rule_info_t *rule;
	const proto_attribute_t *p;

	//for each index
	for( index=0; index< proto_atts_count; index++ ){
		p = proto_atts[ index ];
		//for each rule
		for( i=0; i< rules_count; i++ ){
			rule = rules[ i ];
			rule->hash_message( p->proto, p->att, index );
		}
		mmt_debug("%2d <- hash(%s, %s)", index, p->proto, p->att );
	}
}


/**
 * This function inits security rules
 * @return
 */
int mmt_sec_init( const char* excluded_rules_id ){
	is_init = YES;
	//get all available rules
	rules_count = load_mmt_sec_rules( &rules );

	//Rules to be disabled
	_filter_rules( excluded_rules_id );

	if( rules_count == 0 ){
		mmt_warn("There are no security rules to verify.");
		return 1;
	}

	_get_unique_proto_attts();
	_update_rule_hash_proto_att();

	return 0;
}


void mmt_sec_close(){
	mmt_mem_free( rules );
	rules = NULL;
	rules_count = 0;

	mmt_mem_free( proto_atts );
	proto_atts = NULL;
	proto_atts_count = 0;
}

/**
 *
 * @param dpi_handler
 * @param threads_count: if 0, security will use the lcore of caller
 * @param cores_id
 * @param rules_mask
 * @param verbose
 * @param callback
 * @param user_data
 * @return
 */
mmt_sec_handler_t* mmt_sec_register( size_t threads_count, const uint32_t *cores_id, const char *rules_mask,
		bool verbose, mmt_sec_callback callback, void *args ){

	mmt_sec_handler_t *ret = mmt_mem_alloc(sizeof( mmt_sec_handler_t ));

	size_t i, j;

	//number of threads
	ret->threads_count = threads_count;

	//
	if( unlikely( is_init == NO) )
		mmt_halt("mmt_sec_init must be called before any mmt_sec_register" );

	if( verbose ){
		if( threads_count == 0 )
			mmt_info( "MMT-Security %s is verifying %zu rules having %zu proto.atts using the main thread",
				mmt_sec_get_version_info(),
				rules_count, proto_atts_count );
		else
			mmt_info( "MMT-Security %s is verifying %zu rules having %zu proto.atts using %zu threads",
							mmt_sec_get_version_info(),
							rules_count, proto_atts_count, threads_count );
	}
	//init mmt-sec to verify the rules
	if( threads_count == 0 ){
		ret->sec_handler = mmt_single_sec_register( rules, rules_count, verbose, callback, args );
		ret->process = (void *)&mmt_single_sec_process;
	} else {
		ret->sec_handler = mmt_smp_sec_register( threads_count,
												cores_id, rules_mask, verbose, callback, args );
		ret->process = (void *)&mmt_smp_sec_process;
	}

	return ret;
}

void mmt_sec_process( mmt_sec_handler_t *handler, message_t *msg ){
	handler->process( handler->sec_handler, msg );
}

/**
 * Stop and free mmt_security
 * @param wrapper
 * @return
 */
size_t mmt_sec_unregister( mmt_sec_handler_t* ret ){
	size_t alerts_count = 0;

	if( unlikely( ret == NULL) )
		return 0;

	if( ret->threads_count > 0 )
		alerts_count = mmt_smp_sec_unregister( ret->sec_handler, NO );
	else
		alerts_count = mmt_single_sec_unregister( ret->sec_handler );

	mmt_mem_free( ret );

	return alerts_count;
}


size_t mmt_sec_get_rules_info( const rule_info_t ***rules_array ){
	*rules_array = rules;
	return rules_count;
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
//	static uint32_t alert_index = 0;
	//TODO this limit mmt-sec on max 100 K rules
	static uint8_t  prop_index[100000] = {0}, *p;

//	__sync_add_and_fetch( &alert_index, 1 );


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

	len = snprintf( message, MAX_MSG_SIZE, "10,0,\"\",%ld,%"PRIu32",\"%s\",\"%s\",\"%s\", %s",
			time( NULL ),
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
	size_t i, j, k, size;
	const mmt_array_t *proto_atts;
	const proto_attribute_t *proto;
	struct tm tm;
	char string[ 100000 ], *ch_ptr, tmp_string[ 1000 ];
	string[ 0 ] = '\0';
	ch_ptr = &string[ 0 ];

	printf("Found %zu rule%s", rules_count, rules_count<=1? ".": "s." );

	for( i=0; i<rules_count; i++ ){
		printf("\n%zu - Rule id: %d", (i+1), rules[i]->id );
		printf("\n\t- type            : %s",  rules[i]->type_string );
		printf("\n\t- description     : %s",  rules[i]->description );
		printf("\n\t- if_satisfied    : %s",  rules[i]->if_satisfied );
		printf("\n\t- if_not_satisfied: %s",  rules[i]->if_not_satisfied );
		//for each event
		for(j=0; j<rules[i]->events_count; j++ ){
			printf("\n\t- event %-2zu        ", j+1 );
			//visite each proto/att of one event
			proto_atts = &(rules[i]->proto_atts_events[ j+1 ]);
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

		tm = *localtime(& rules[i]->version->created_date );
		printf("\n\t- version         : %s (%s - %d-%d-%d %d:%d:%d), dpi version %s",
				 rules[i]->version->number,
				 rules[i]->version->hash,
				 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
				 rules[i]->version->dpi );
	}

	//remove the last comma
	size = strlen( string );
	if( size > 0 ) string[ size - 1 ] = '\0';

	printf("\n\nProtocols and their attributes used in these rules:\n\t %s\n\n", string );
}


size_t mmt_sec_get_unique_protocol_attributes( const proto_attribute_t ***proto_atts_array ){
	*proto_atts_array = proto_atts;
	return proto_atts_count;
}


uint16_t mmt_sec_hash_proto_attribute( uint32_t proto_id, uint32_t att_id ){
	int i;
	for( i=0; i<proto_atts_count; i++ )
		if( proto_atts[ i ]->att_id  == att_id && proto_atts[ i ]->proto_id  == proto_id )
			return i;

	mmt_halt( "Attribute %d.%d has not been registered in MMT-Security", proto_id, att_id );
	return 0;
}
