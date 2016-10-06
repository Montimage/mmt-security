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


#define STR_BUFFER_SIZE 10000
#define _gen_comment( fd, format, ... ) fprintf( fd, "\n/** %d\n * " format "\n */\n", __LINE__, ##__VA_ARGS__ )
#define _gen_one_line_comment( fd, format, ... ) fprintf( fd, "/** %d " format "*/", __LINE__, ##__VA_ARGS__ )
#define _gen_code_line( fd ) fprintf( fd, "/* %d */", __LINE__ )
#define _val( x ) (x==NULL? "NULL": x)

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



static void _iterate_variable( void *key, void *data, void *user_data, size_t index, size_t total ){
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

static void _iterate_event_to_gen_guards( void *key, void *data, void *user_data, size_t index, size_t total ){
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
	fprintf(fd, "\n\n\treturn %s;\n}\n",  str);

	mmt_free( str );
	//add events to list events
	//mmt_map_set_data(u_data->events_map, guard_fun_name, map, NO);
	mmt_map_free( map, NO );
	mmt_free( guard_fun_name );
}

#define MAX_STR_BUFFER 10000
enum _event_type{ _TIMEOUT, _EVENT };
typedef struct _state_struct{
	size_t index;
	char *description;
	rule_delay_t *delay;
	link_node_t *transitions;
	char comment[MAX_STR_BUFFER];
	char *action;
}_state_t;

typedef struct _transition_struct{
	int event_type;
	char *condition;
	int guard_id;
	char *action;
	_state_t *target;
	const rule_event_t *attached_event;//
}_transition_t;

static inline _state_t *_create_new_state( index ){
	_state_t *s = mmt_malloc( sizeof( _state_t ));
	s->index = index;
	s->description = NULL;
	s->delay = NULL;
	s->transitions = NULL;
	s->action = NULL;
	s->comment[0] = '\0';
	return s;
}

static inline _transition_t *_create_new_transition( int event_type, int guard_id, _state_t *target, const rule_event_t *ev){
	_transition_t *t = mmt_malloc( sizeof( _transition_t ));
	t->event_type = event_type;
	t->condition  = NULL;
	t->guard_id   = guard_id;
	t->action     = NULL;
	t->target     = target;
	t->attached_event = ev;
	return t;
}

static inline void _gen_transition_rule( _state_t *s_init, _state_t *s_final,  _state_t *s_error,
		link_node_t *states_list, const  rule_node_t *rule_node, size_t *index,  const rule_t *rule);

/**
 * a THEN b
 * target state of a is the source state of b
 */
static inline void _gen_transition_then( _state_t *s_init,  _state_t *s_final,  _state_t *s_error,
		link_node_t *states_list, const  rule_node_t *context, const  rule_node_t *trigger,
		size_t *index, const rule_operator_t *operator, const rule_t *rule){

	_state_t *state = _create_new_state( 0 );
	//root
	if( operator == NULL ){
		state->description = rule->description;
		state->delay       = rule->delay;
		snprintf(state->comment, MAX_STR_BUFFER, "root node");
	}else{
		state->description = operator->description;
		state->delay       = operator->delay;
	}

	//add timeout transition
	state->transitions = append_node_to_link_list( state->transitions,
			_create_new_transition( _TIMEOUT, 0, s_final, NULL));

	//gen for context
	_gen_transition_rule( s_init, state, s_error, states_list, context, index, rule );
	//increase index
	state->index = (*index)++;
	states_list  = append_node_to_link_list( states_list, state );
	//gen for trigger
	_gen_transition_rule( state, s_final, s_error, states_list, trigger, index, rule );
}

/**
 * a AND b == (a THEN b) OR (b THEN a)
 */
static inline void _gen_transition_and( _state_t *s_init,  _state_t *s_final,  _state_t *s_error,
		link_node_t *states_list, const  rule_node_t *context, const  rule_node_t *trigger,
		size_t *index, const rule_operator_t *operator, const rule_t *rule){

	_gen_transition_then( s_init, s_final, s_error, states_list, context, trigger, index, operator, rule );
	_gen_transition_then( s_init, s_final, s_error, states_list, trigger, context, index, operator, rule );
}

/**
 * a OR b
 * a and b having the same source and target states
 */
static inline void _gen_transition_or( _state_t *s_init,  _state_t *s_final,  _state_t *s_error,
		link_node_t *states_list, const  rule_node_t *context, const  rule_node_t *trigger,
		size_t *index, const rule_operator_t *operator, const rule_t *rule){

	_gen_transition_rule( s_init, s_final, s_error, states_list, context, index, rule );
	_gen_transition_rule( s_init, s_final, s_error, states_list, trigger, index, rule );
}

/**
 * a NOT b
 *
 */
static inline void _gen_transition_not( _state_t *s_init,  _state_t *s_final,  _state_t *s_error,
		link_node_t *states_list, const  rule_node_t *context, const  rule_node_t *trigger,
		size_t *index, const rule_operator_t *operator, const rule_t *rule){

	_state_t *state = _create_new_state( 0 );
	//root
	if( operator == NULL ){
		state->description = rule->description;
		state->delay       = rule->delay;
		snprintf(state->comment, MAX_STR_BUFFER, "root node");
	}else{
		state->description = operator->description;
		state->delay       = operator->delay;
	}

	//add timeout transition
	state->transitions = append_node_to_link_list( state->transitions,
			_create_new_transition( _TIMEOUT, 0, s_final, NULL));

	//gen for context
	_gen_transition_rule( s_init, state, s_error, states_list, context, index, rule );
	//increase index
	state->index = (*index)++;
	states_list  = append_node_to_link_list( states_list, state );
	//gen for trigger
	_gen_transition_rule( state, s_error, s_final, states_list, trigger, index, rule );
}

static inline void _gen_transition_rule( _state_t *s_init,  _state_t *s_final,  _state_t *s_error,
		link_node_t *states_list, const  rule_node_t *rule_node, size_t *index, const rule_t *rule){

	rule_operator_t *opt;

	if( rule_node->type == RULE_EVENT ){

		s_init->transitions = append_node_to_link_list( s_init->transitions,
				_create_new_transition(_EVENT, rule_node->event->id, s_final, rule_node->event ));
		return;
	}

	opt = rule_node->operator;
	switch( opt->value){
	case OP_TYPE_THEN:
		_gen_transition_then(s_init, s_final, s_error, states_list, opt->context, opt->trigger, index, opt, rule);
		break;
	case OP_TYPE_AND:
		_gen_transition_and(s_init, s_final, s_error, states_list, opt->context, opt->trigger, index, opt, rule);
		break;
	case OP_TYPE_OR:
		_gen_transition_or(s_init, s_final, s_error, states_list, opt->context, opt->trigger, index, opt, rule);
		break;
	case OP_TYPE_NOT:
		_gen_transition_not(s_init, s_error, s_final, states_list, opt->context, opt->trigger, index, opt, rule);
		break;
	}
}

static void _gen_fsm( FILE *fd, const rule_t *rule, mmt_map_t *variables_map ){
	mmt_map_t *map;
	size_t size, index;
	struct _user_data u_data;
	_state_t *s_init, *s_error, *s_final, *state;
	_transition_t *tran;
	link_node_t *states_list = NULL, *p_link_node, *p_t;
	char buffer[ MAX_STR_BUFFER ];

	if( rule == NULL || fd == NULL ) return;
	/*generate guard functions*/
	_gen_comment( fd, "==================Rule %d====================\n * %s", rule->id, rule->description );

	size = get_unique_events_of_rule( rule, &map );
	if( size == 0 ) return;

	u_data.index=rule->id;
	u_data.file=fd;
	u_data.variables_map = variables_map;

	mmt_map_iterate(map, _iterate_event_to_gen_guards, &u_data );

	/*generate fsm states*/
	_gen_comment( fd, "States of FSM for rule %d", rule->id );


	index = 0;
	s_init = _create_new_state( index ++ );
	s_error = _create_new_state( index ++ );
	s_final = _create_new_state( index ++ );

	sprintf(s_init->comment, "initial state");
	s_init->description = rule->description;

	sprintf(s_final->comment, "final state");
	s_final->action = rule->if_satisfied;

	sprintf( s_error->comment, "timeout/error state");
	s_error->action = rule->if_not_satisfied;

	states_list = append_node_to_link_list(states_list, s_init );
	states_list = append_node_to_link_list(states_list, s_error );
	states_list = append_node_to_link_list(states_list, s_final );

	_gen_transition_then(s_init, s_final, s_error, states_list, rule->context, rule->trigger, &index, NULL, rule);


	_gen_comment(fd, "Predefine list of states: init, error, final, ..." );
	fprintf(fd, "static fsm_state_t");
	p_link_node = states_list;
	while( p_link_node != NULL ){
		state = (_state_t *)p_link_node->data;
		fprintf( fd, " s_%d_%zu%c", rule->id, state->index, (p_link_node->next == NULL? ';':',') );

		p_link_node = p_link_node->next;
	}

	/**
	 * Print detail of each state
	 */
	_gen_comment(fd, "Initialize states: init, error, final, ..." );
	fprintf(fd, "static fsm_state_t");
	p_link_node = states_list;
	while( p_link_node != NULL ){
		state = (_state_t *)p_link_node->data;
		if( strlen( state->comment ))
			_gen_comment(fd, "%s", state->comment );

		fprintf( fd, " s_%d_%zu = {", rule->id, state->index );
		fprintf( fd, "\n\t.timer        = 0,");
		fprintf( fd, "\n\t.counter      = 0,");
		fprintf( fd, "\n\t.delay        = ");
		if( state->delay )
			fprintf( fd, "(fsm_delay_t *){.time_min = %.2f, .time_max = %.2f, .counter_min = %d, .counter_max = %d},",
				state->delay->time_min, state->delay->time_max,
				state->delay->counter_min, state->delay->counter_max);
		else
			fprintf( fd, "NULL,");
		fprintf( fd, "\n\t.description  = ");
		if( state->description )
			fprintf( fd, "\"%s\",", state->description );
		else
			fprintf( fd, "NULL," );

		fprintf( fd, "\n\t.exit_action  = ");
		if( state->action )
			fprintf( fd, "exec(\"%s\"),", state->action );
		else
			fprintf( fd, "NULL,");
		fprintf( fd, "\n\t.entry_action = NULL,");

		size = 0;
		//print list of outgoing transitions of this state
		if( state->transitions == NULL ){
			fprintf( fd, "\n\t.transitions  = NULL,");
		}else{
			fprintf( fd, "\n\t.transitions  = (fsm_transition_t[]){");
			p_t = state->transitions;
			while( p_t != NULL ){
				size ++;
				tran = (_transition_t *)p_t->data;
				if( tran->attached_event && tran->attached_event->description )
					fprintf( fd, "\n\t\t/** %d %s */", __LINE__, tran->attached_event->description );
				sprintf( buffer, "&g_%d_%d", rule->id, tran->guard_id );
				fprintf( fd, "\n\t\t{ %s, NULL, %s, NULL, &s_%d_%zu}%c",
						(tran->event_type == _TIMEOUT ? "TIMEOUT" : "EVENT  "),
						(tran->event_type == _TIMEOUT ? "NULL  "    : buffer   ),
						rule->id, tran->target->index,
						(p_t->next == NULL?' ':',')
				);
				p_t = p_t->next;
			}
			fprintf( fd, "\n\t},");
			free_link_list( state->transitions, YES );
		}

		fprintf( fd, "\n\t.transitions_count = %zu", size );

		fprintf( fd, "\n}%c", (p_link_node->next == NULL? ';':',') );
		p_link_node = p_link_node->next;
	}
	_gen_comment( fd, "Create a new FSM");
	fprintf( fd, "inline fsm_t * new_fsm_%d(){ return fsm_init( &s_%d_%zu, &s_%d_%zu );}\n",
			rule->id, rule->id, s_init->index, rule->id, s_error->index );

	free_link_list( states_list, YES );
	mmt_map_free( map, NO );
}

void _iterate_variables_to_print_switch( void *key, void *data, void *arg, size_t index, size_t total){
	static uint32_t last_proto_id = UNKNOWN, cur_proto_id;

	FILE *fd = (FILE *)arg;
	variable_t *var = (variable_t *)data;

	cur_proto_id  = var->proto_id;

	if( last_proto_id != cur_proto_id ){
		if( last_proto_id != (uint32_t)UNKNOWN ){
			fprintf(fd, "\n\t\tdefault:\n\t\t\tfprintf(stderr, \"Do not find attribute %%d of protocol %d in the given rules.\", att_id);\n\t\t\texit(1);", last_proto_id );
			fprintf(fd, "\n\t\t}//end att for %d", last_proto_id ); //close the previous switch
		}
		_gen_comment( fd, "%s", var->proto );
		fprintf(fd, "\tcase %d:", cur_proto_id );
		fprintf(fd, "\n\t\tswitch ( att_id){");
	}
	fprintf(fd, "\n\t\tcase %d:\t//%s", var->att_id, var->att );
	fprintf(fd, "\n\t\t\treturn %zu;", index );

	if( index == total-1 ){
		fprintf(fd, "\n\t\tdefault:\n\t\t\tfprintf(stderr, \"Do not find attribute %%d of protocol %d in the given rules.\", att_id);\n\t\t\texit(1);", last_proto_id );
		fprintf(fd, "\n\t\t}//last switch");
	}

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
	fprintf( fd, "\n\tdefault:\n\t\tfprintf(stderr, \"Do not find protocol %%d in the given rules.\", proto_id);\n\t\texit(1);");
	fprintf( fd, "\n\t}"); //end switch
	fprintf( fd, "\n}");//end function
}

inline void _iterate_to_free_key_and_data( void *key, void *data, void *user_data, size_t index, size_t total ){
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
	fprintf( fd, "#include <string.h>\n#include \"base.h\"\n#include \"mmt_fsm.h\"\n");

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
