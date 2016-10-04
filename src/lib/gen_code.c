/*
 * gen_code.c
 *
 *  Created on: 4 oct. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "gen_code.h"
#include "data_struct.h"
#include "expression.h"
#include "mmt_log.h"
#include "mmt_alloc.h"
#include "../mmt_dpi.h"

#define STR_BUFFER_SIZE 10000
#define _gen_comment fprintf

struct _user_data{
	uint16_t index;
	void *data;
};

enum data_types {
    MMT_UNDEFINED_TYPE, /**< no type constant value */
    MMT_U8_DATA, /**< unsigned 1-byte constant value */
    MMT_U16_DATA, /**< unsigned 2-bytes constant value */
    MMT_U32_DATA, /**< unsigned 4-bytes constant value */
    MMT_U64_DATA, /**< unsigned 8-bytes constant value */
    MMT_DATA_POINTER, /**< pointer constant value (size is void *) */
    MMT_DATA_MAC_ADDR, /**< ethernet mac address constant value */
    MMT_DATA_IP_NET, /**< ip network address constant value */
    MMT_DATA_IP_ADDR, /**< ip address constant value */
    MMT_DATA_IP6_ADDR, /**< ip6 address constant value */
    MMT_DATA_PATH, /**< protocol path constant value */
    MMT_DATA_TIMEVAL, /**< number of seconds and microseconds constant value */
    MMT_DATA_BUFFER, /**< binary buffer content */
    MMT_DATA_CHAR, /**< 1 character constant value */
    MMT_DATA_PORT, /**< tcp/udp port constant value */
    MMT_DATA_POINT, /**< point constant value */
    MMT_DATA_PORT_RANGE, /**< tcp/udp port range constant value */
    MMT_DATA_DATE, /**< date constant value */
    MMT_DATA_TIMEARG, /**< time argument constant value */
    MMT_DATA_STRING_INDEX, /**< string index constant value (an association between a string and an integer) */
    MMT_DATA_FLOAT, /**< float constant value */
    MMT_DATA_LAYERID, /**< Layer ID value */
    MMT_DATA_FILTER_STATE, /**< (filter_id, filter_state) */
    MMT_DATA_PARENT, /**< (filter_id, filter_state) */
    MMT_STATS, /**< pointer to MMT Protocol statistics */
    MMT_BINARY_DATA, /**< binary constant value */
    MMT_BINARY_VAR_DATA, /**< binary constant value with variable size given by function getExtractionDataSizeByProtocolAndFieldIds */
    MMT_STRING_DATA, /**< text string data constant value. Len plus data. Data is expected to be '\0' terminated and maximum BINARY_64DATA_LEN long */
    MMT_STRING_LONG_DATA, /**< text string data constant value. Len plus data. Data is expected to be '\0' terminated and maximum STRING_DATA_LEN long */
    MMT_HEADER_LINE, /**< string pointer value with a variable size. The string is not necessary null terminating */
    MMT_GENERIC_HEADER_LINE, /**< structure representing an RFC2822 header line with null terminating field and value elements. */
    MMT_STRING_DATA_POINTER, /**< pointer constant value (size is void *). The data pointed to is of type string with null terminating character included */
};

static enum data_type _get_attribute_data_type( const char*proto, const char*attr ){
	uint32_t p_id, a_id;
	p_id = get_protocol_id_by_name( proto );
	a_id = get_attribute_id_by_protocol_id_and_attribute_name( p_id, attr );
	long type = get_attribute_data_type( p_id, a_id );
	switch( type ){
	case MMT_U16_DATA:
	case MMT_U32_DATA:
	case MMT_U64_DATA:
	case MMT_U8_DATA:
	case MMT_DATA_PORT:
	case MMT_DATA_CHAR:
	case MMT_DATA_FLOAT:
		return NUMERIC;

	case MMT_DATA_MAC_ADDR:
	case MMT_STRING_DATA:
	case MMT_DATA_PATH:
	case MMT_STRING_LONG_DATA:
	case MMT_BINARY_VAR_DATA:
	case MMT_BINARY_DATA:
	case MMT_HEADER_LINE:
	case MMT_DATA_TIMEVAL:
	case MMT_DATA_IP_ADDR:
	case MMT_DATA_IP6_ADDR:
	case MMT_DATA_PORT_RANGE:
	case MMT_DATA_DATE:
	case MMT_DATA_TIMEARG:
	case MMT_DATA_IP_NET:
	case MMT_DATA_LAYERID:
	case MMT_DATA_POINT:
	case MMT_DATA_FILTER_STATE:
	case MMT_DATA_POINTER:
	case MMT_DATA_BUFFER:
	case MMT_DATA_STRING_INDEX:
	case MMT_DATA_PARENT:
	case MMT_STATS:
	case MMT_GENERIC_HEADER_LINE:
	case MMT_STRING_DATA_POINTER:
	case MMT_UNDEFINED_TYPE:
		return STRING;
	default:
		mmt_assert(0, "Error 2: Type [%ld], not implemented yet, data type unknown.\n", type);
	}
	return STRING;
}

static void _iterate_variable( void *key, void *data, void *user_data ){
	char *str = NULL, *buffer = (char *)user_data, *ptr;
	size_t size;
	variable_t *var = (variable_t *) data;

	size = strlen( buffer );
	if( size >= STR_BUFFER_SIZE )
		return;

	ptr = buffer + size;

	size = expr_stringify_variable( &str, var );
	if( size == 0 ) return;


	var->type = _get_attribute_data_type( var->proto, var->att );
	if( var->type == NUMERIC )
		snprintf( ptr, STR_BUFFER_SIZE - size - 1, ", double %s", str );
	else
		snprintf( ptr, STR_BUFFER_SIZE - size - 1, ", char* %s", str );

	mmt_free( str );
}

static void _iterate_event( void *key, void *data, void *user_data ){
	char *str = NULL;
	size_t size;
	mmt_map_t *map;
	char buffer[ STR_BUFFER_SIZE ] = "";
	rule_event_t *event = (rule_event_t *)data;
	struct _user_data *u_data = (struct _user_data *) user_data;
	FILE *fd = u_data->data;

	_gen_comment( fd, "\n/**\n * Rule %d, event %d\n * %s\n */\n", u_data->index, event->id, event->description );
	size = expr_stringify_expression( &str, event->expression );
	if( size == 0 ) return;

	//set of variables
	size = get_unique_variables_of_expression( event->expression, &map, YES );
	mmt_map_iterate( map, _iterate_variable, buffer );

	//guard function header
	fprintf(fd, "static inline int guard_%d_%d(%s ){", u_data->index, event->id, buffer+1 );
	fprintf(fd, "\n\treturn %s;\n}\n",  str);

	mmt_free( str );
	mmt_map_free( map, NO );
}

static void _gen_fsm( FILE *fd, const rule_t *rule ){
	mmt_map_t *map;
	size_t size;
	struct _user_data u_data;

	if( rule == NULL || fd == NULL ) return;
	/*generate guard functions*/
	_gen_comment( fd, "\n/*===Guards for rule %d===*/\n", rule->id );

	size = get_unique_events_of_rule( rule, &map );
	if( size == 0 ) return;

	u_data.index=rule->id;
	u_data.data=fd;

	mmt_map_iterate(map, _iterate_event, &u_data );

	mmt_map_free( map, NO );
}

/**
 * Public API
 */
enum bool generate_fsm( const char* file_name, rule_t *const* rules, size_t count ){

	size_t i;
	FILE *fd = fopen(file_name, "w");

	mmt_assert (fd != NULL, "Error 11a: Cannot open file %s for writing", file_name );

	for( i=0; i<count; i++ )
		_gen_fsm( fd, rules[i] );

	fclose(fd);
	return YES;
}
