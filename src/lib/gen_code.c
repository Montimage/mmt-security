/*
 * gen_code.c
 *
 *  Created on: 4 oct. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "gen_code.h"
#include "mmt_utils.h"
#include "data_struct.h"
#include "expression.h"
#include "mmt_log.h"
#include "mmt_alloc.h"
#include "../mmt_dpi.h"

#define STR_BUFFER_SIZE 10000
#define _gen_comment( fd, format, ... ) fprintf( fd, "\n/** %d\n * " format "\n */\n", __LINE__, ##__VA_ARGS__ )
#define _gen_code_line( fd ) fprintf( fd, "/* %d */", __LINE__ )

struct _user_data{
	uint16_t index;
	FILE *file;
	mmt_map_t *variables_map, *events_map;
};

static inline uint64_t _simple_hash( uint32_t a, uint32_t b ){
	uint64_t c = a << 31;
	return c | b;
}

struct _variables_struct{
	char *proto, *att;
	uint32_t data_type, proto_id, att_id;
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

static enum data_type _get_attribute_data_type( uint32_t p_id, uint32_t a_id ){
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

static void _iterate_variable( void *key, void *data, void *user_data, enum bool is_first, enum bool is_last ){
	char *str = NULL;
	struct _user_data *u_data = (struct _user_data *) user_data;
	FILE *fd  = u_data->file;
	size_t size;
	variable_t *var = (variable_t *) data;
	uint32_t p_id, a_id;

	//add variable to the list of unique variables
	mmt_map_set_data( u_data->variables_map, var, var, NO );

	size = expr_stringify_variable( &str, var );
	if( size == 0 ) return;

	p_id = get_protocol_id_by_name( var->proto );
	a_id = get_attribute_id_by_protocol_id_and_attribute_name( p_id, var->att );
	var->data_type = _get_attribute_data_type( p_id, a_id );

	_gen_code_line( fd );
	fprintf( fd, "\n\t%s%s = ",
			((var->data_type == NUMERIC)? "double " : "const char *"),
			str);

	//TODO: when proto starts by a number
	if( var->ref_index != (uint8_t)UNKNOWN )
		fprintf( fd, "((report_t *)fsm_get_history( fsm, %d ))->%s_%s;",
				var->ref_index, var->proto, var->att);
	else
		fprintf( fd, "((report_t *)event->data)->%s;", str );

	mmt_free( str );
}

static void _iterate_event_to_gen_guards( void *key, void *data, void *user_data, enum bool is_first, enum bool is_last ){
	char *str = NULL, *guard_fun_name, buffer[1000];
	size_t size;
	mmt_map_t *map;
	rule_event_t *event = (rule_event_t *)data;
	struct _user_data *u_data = (struct _user_data *) user_data;
	FILE *fd = u_data->file;

	_gen_comment( fd, "Rule %d, event %d\n * %s", u_data->index, event->id, event->description );
	size = expr_stringify_expression( &str, event->expression );
	if( size == 0 ) return;

	//set of variables
	size = get_unique_variables_of_expression( event->expression, &map, YES );

	//name of function
	size = snprintf( buffer, sizeof( buffer ) -1, "g_%d_%d", u_data->index, event->id );
	//do not free this as it will be used as a key in variables_map
	guard_fun_name = mmt_mem_dup( buffer, size );

	//guard function header
	fprintf(fd, "static inline int %s( void *condition, const fsm_event_t *event, const fsm_t *fsm ){",
			guard_fun_name );
	mmt_map_iterate( map, _iterate_variable, u_data );
	fprintf(fd, "\n\n\treturn *(uint8_t *)condition == %s;\n}\n",  str);

	mmt_free( str );
	//add events to list events
	//mmt_map_set_data(u_data->events_map, guard_fun_name, map, NO);
	mmt_map_free( map, NO );
	mmt_free( guard_fun_name );
}

static void _gen_fsm( FILE *fd, const rule_t *rule, mmt_map_t *variables_map ){
	mmt_map_t *map;
	size_t size;
	struct _user_data u_data;

	if( rule == NULL || fd == NULL ) return;
	/*generate guard functions*/
	_gen_comment( fd, "===Guards for rule %d===", rule->id );

	size = get_unique_events_of_rule( rule, &map );
	if( size == 0 ) return;

	u_data.index=rule->id;
	u_data.file=fd;
	u_data.variables_map = variables_map;

	mmt_map_iterate(map, _iterate_event_to_gen_guards, &u_data );

	/*generate fsm states*/
	_gen_comment( fd, "States of FSM for rule %d", rule->id );
	fprintf( fd, "static fsm_state_t state_%d_%d;\n", rule->id, rule->id );


	mmt_map_free( map, NO );
}

void _iterate_variables_to_print_switch( void *key, void *data, void *arg, enum bool is_first, enum bool is_last){
	static uint32_t last_proto_id = UNKNOWN, cur_proto_id;
	static uint8_t index = 0;

	FILE *fd = (FILE *)arg;
	variable_t *var = (variable_t *)data;

	cur_proto_id  = get_protocol_id_by_name( var->proto );

	if( last_proto_id != cur_proto_id ){
		if( last_proto_id != (uint32_t)UNKNOWN )
				fprintf(fd, "\n\t\t}//end"); //close the previous switch

		_gen_comment( fd, "%s", var->proto );
		fprintf(fd, "\tcase %d:", cur_proto_id );
		fprintf(fd, "\n\t\tswitch ( att_id){");
	}
	fprintf(fd, "\n\t\tcase %d:", get_attribute_id_by_protocol_id_and_attribute_name( cur_proto_id, var->att));
	fprintf(fd, "\n\t\t\treturn %d;", (index++));
	if( is_first )
		fprintf(fd, "\n\t\t}//fistr");
	if( is_last == YES )
		fprintf(fd, "\n\t\t}//last");


	last_proto_id = cur_proto_id;
}
/**
 * Generate a hash function of variables
 */
void _gen_hash_fun_of_proto_att( FILE *fd, const mmt_map_t *variables_map){
	_gen_comment( fd, "HASH" );
	fprintf( fd, "inline uint16_t hash_proto_attribute( uint32_t proto_id, uint32_t att_id){");
	fprintf( fd, "\n\tswitch( proto_id ){");

	mmt_map_iterate( variables_map, _iterate_variables_to_print_switch, fd );

	fprintf( fd, "\n\t}"); //end switch
	fprintf( fd, "\n}");//end function
}

inline void _iterate_to_free_key_and_data( void *key, void *data, void *user_data, enum bool is_first, enum bool is_last ){
	mmt_free( key );
	mmt_map_free( (mmt_map_t *) data, NO );
}
/**
 * Public API
 */
int generate_fsm( const char* file_name, rule_t *const* rules, size_t count ){
	char *str_ptr;
	size_t i;
	/**
	 * a set of variables using in each guard function
	 * <fun_name, map>
	 */
	mmt_map_t *events_map = mmt_map_init( &compare_string );
	mmt_map_t *variables_map =  mmt_map_init( &compare_variable_name );

	FILE *fd = fopen(file_name, "w");

	mmt_assert (fd != NULL, "Error 11a: Cannot open file %s for writing", file_name );

	str_ptr = get_current_date_time_string( "%Y-%m-%d %H:%M:%S" );
	_gen_comment( fd, "This file is generated automatically on %s", str_ptr);
	mmt_free( str_ptr );

	//include
	fprintf( fd, "#include \"base.h\"\n#include \"mmt_fsm.h\"\n");

	//fsm states
	fprintf( fd, "\nstatic fsm_state_t state_init, state_final;");
	_gen_comment( fd, "Create a new FSM");
	fprintf( fd, "inline fsm_t * create_new_fsm(){ return fsm_init( &state_init, &state_final );}\n" );

	for( i=0; i<count; i++ )
		_gen_fsm( fd, rules[i], variables_map );

	_gen_hash_fun_of_proto_att( fd, variables_map );

	fclose(fd);

	mmt_map_iterate( events_map, _iterate_to_free_key_and_data, NULL );
	mmt_map_free( events_map, NO );

	mmt_map_free( variables_map, NO );
	return 0;
}


int compile_gen_code( const char *lib_file, const char *code_file ){
	char cmd_str[ 10000 ];
	sprintf( cmd_str, "/usr/bin/gcc -shared %s -o %s", code_file, lib_file );
	return system ( cmd_str );
}
