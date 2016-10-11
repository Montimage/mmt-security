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
#include "mmt_fsm.h"
#include "mmt_log.h"
#include "mmt_alloc.h"


#define STR_BUFFER_SIZE 10000
#define _gen_comment( fd, format, ... ) fprintf( fd, "\n/** %d\n * " format "\n */\n", __LINE__, ##__VA_ARGS__ )
#define _gen_comment_line( fd, format, ... ) fprintf( fd, "/** %d " format "*/", __LINE__, ##__VA_ARGS__ )
#define _gen_code_line( fd ) fprintf( fd, "/* %d */", __LINE__ )
#define _val( x ) (x==NULL? "NULL": x)
#define _string( v, a,b,c, x,y,z  ) (v==NULL? a:x), (v==NULL? b:y), (v==NULL? c:z)


struct _user_data{
	uint16_t index;
	mmt_map_t *events_map;
	FILE *file;
};

static inline uint32_t _simple_hash_32( uint16_t a, uint16_t b ){
	uint32_t val = 0;
	val = a << 16;
	val = val | b;
	return val;
}

static inline void _simple_dehash_32( uint32_t val, uint16_t *a, uint16_t *b){
	*a = val >> 16;
	*b = (val << 16) >> 16;
}

struct _variables_struct{
	char *proto, *att;
	uint32_t data_type, proto_id, att_id;
};


static void _iterate_variable( void *key, void *data, void *user_data, size_t index, size_t total ){
	char *str = NULL;
	struct _user_data *_u_data = (struct _user_data *)user_data;
	FILE *fd = _u_data->file;
	uint32_t rule_id  = _u_data->index;

	size_t size;
	variable_t *var = (variable_t *) data;
	uint32_t p_id, a_id;

	size = expr_stringify_variable( &str, var );
	if( size == 0 ) return;

	_gen_code_line( fd );
	fprintf( fd, "\n\t%s%s = ((_msg_t_%d *)",
			((var->data_type == NUMERIC)? "double " : "const char *"),
			str, rule_id);

	//TODO: when proto starts by a number
	if( var->ref_index != (uint8_t)UNKNOWN )
		fprintf( fd, "fsm_get_history( fsm, %d ))->%s_%s;",
				var->ref_index, var->proto, var->att);
	else
		fprintf( fd, "event->data)->%s;", str );

	//TODO: not need to check ?
	//if( var->data_type != NUMERIC )
		fprintf( fd, "\n\tif( %s == NULL ) return 0;", str );

	mmt_free( str );
}

static void _iterate_event_to_gen_guards( void *key, void *data, void *user_data, size_t index, size_t total ){
	char *str = NULL, *guard_fun_name, buffer[1000];
	size_t size;
	mmt_map_t *map;
	rule_event_t *event = (rule_event_t *)data;
	struct _user_data *_u_data = (struct _user_data *)user_data;
	FILE *fd = _u_data->file;
	uint32_t rule_id  = _u_data->index;
	uint16_t event_id = event->id;

	_gen_comment( fd, "Rule %d, event %d\n * %s", rule_id, event_id, event->description );
	size = expr_stringify_expression( &str, event->expression );
	if( size == 0 ) return;

	//set of variables
	size = get_unique_variables_of_expression( event->expression, &map, YES );

	//name of function
	size = snprintf( buffer, sizeof( buffer ) -1, "g_%d_%d", rule_id, event_id );
	//do not free this as it will be used as a key in variables_map
	guard_fun_name = mmt_mem_dup( buffer, size );

	//guard function header
	fprintf(fd, "static inline int %s( void *condition, const fsm_event_t *event, const fsm_t *fsm ){",
			guard_fun_name );
	mmt_map_iterate( map, _iterate_variable, user_data );
	fprintf(fd, "\n\n\treturn %s;\n}\n",  str);

	mmt_free( str );
	//add events to list events
	//mmt_map_set_data(u_data->events_map, guard_fun_name, map, NO);
	mmt_map_free( map, NO );
	mmt_free( guard_fun_name );
}

////////////////////////////////////////////////////////////////////////////////
#define MAX_STR_BUFFER 10000
/**
 * Meta-model
 * This structure contains information to generate fsm_state_t
 */
typedef struct _meta_state_struct{
	size_t index;
	char *description;
	rule_delay_t *delay;
	link_node_t *transitions;
	char comment[MAX_STR_BUFFER];
	int entry_action;
	int exit_action;
}_meta_state_t;
/**
 * Meta-model
 * This structure contains information to generate fsm_transition_t
 */
typedef struct _meta_transition_struct{
	int event_type;
	char *condition;
	int guard_id;
	char *action;
	_meta_state_t *target;
	const rule_event_t *attached_event;//
	char comment[MAX_STR_BUFFER];
}_meta_transition_t;

static inline _meta_state_t *_create_new_state( index ){
	_meta_state_t *s = mmt_malloc( sizeof( _meta_state_t ));
	s->index        = index;
	s->description  = NULL;
	s->delay        = NULL;
	s->transitions  = NULL;
	s->entry_action = FSM_ACTION_DO_NOTHING;
	s->exit_action  = FSM_ACTION_DO_NOTHING;
	s->comment[0]   = '\0';
	return s;
}

static inline _meta_transition_t *_create_new_transition( int event_type, int guard_id, _meta_state_t *target, const rule_event_t *ev, const char *comment){
	_meta_transition_t *t = mmt_malloc( sizeof( _meta_transition_t ));
	t->event_type = event_type;
	t->condition  = NULL;
	t->guard_id   = guard_id;
	t->action     = NULL;
	t->target     = target;
	t->attached_event = ev;
	if( comment != NULL )
		snprintf(t->comment, STR_BUFFER_SIZE, "%s", comment);
	else
		t->comment[0] = '\0';
	return t;
}

static inline void _gen_transition_rule( _meta_state_t *s_init, _meta_state_t *s_final,  _meta_state_t *s_error,
		link_node_t *states_list, const  rule_node_t *rule_node, size_t *index,  const rule_t *rule);

/**
 * a THEN b
 * target state of a is the source state of b
 */
static inline void _gen_transition_then( _meta_state_t *s_init,  _meta_state_t *s_final,  _meta_state_t *s_error,
		link_node_t *states_list, const  rule_node_t *context, const  rule_node_t *trigger,
		size_t *index, const rule_operator_t *operator, const rule_t *rule){

	_meta_state_t *state = _create_new_state( 0 );
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
			_create_new_transition( FSM_EVENT_TIMEOUT, 0, s_final, NULL, NULL));

	//gen for context
	_gen_transition_rule( s_init, state, s_error, states_list, context, index, rule );
	//increase index
	state->index = (*index)++;
	states_list  = append_node_to_link_list( states_list, state );
	//gen for trigger
	_gen_transition_rule( state, s_final, s_error, states_list, trigger, index, rule );
	//create a new loop-itself
	if( context->type == RULE_EVENT ){
		state->exit_action = FSM_ACTION_CREATE_INSTANCE;
		state->transitions = append_node_to_link_list( state->transitions,
				_create_new_transition( FSM_EVENT, context->event->id, state, NULL, "Loop to create a new instance"));
	}
}

/**
 * a AND b == (a THEN b) OR (b THEN a)
 */
static inline void _gen_transition_and( _meta_state_t *s_init,  _meta_state_t *s_final,  _meta_state_t *s_error,
		link_node_t *states_list, const  rule_node_t *context, const  rule_node_t *trigger,
		size_t *index, const rule_operator_t *operator, const rule_t *rule){

	_gen_transition_then( s_init, s_final, s_error, states_list, context, trigger, index, operator, rule );
	_gen_transition_then( s_init, s_final, s_error, states_list, trigger, context, index, operator, rule );
}

/**
 * a OR b
 * a and b having the same source and target states
 */
static inline void _gen_transition_or( _meta_state_t *s_init,  _meta_state_t *s_final,  _meta_state_t *s_error,
		link_node_t *states_list, const  rule_node_t *context, const  rule_node_t *trigger,
		size_t *index, const rule_operator_t *operator, const rule_t *rule){

	_gen_transition_rule( s_init, s_final, s_error, states_list, context, index, rule );
	_gen_transition_rule( s_init, s_final, s_error, states_list, trigger, index, rule );
}

/**
 * a NOT b
 *
 */
static inline void _gen_transition_not( _meta_state_t *s_init,  _meta_state_t *s_final,  _meta_state_t *s_error,
		link_node_t *states_list, const  rule_node_t *context, const  rule_node_t *trigger,
		size_t *index, const rule_operator_t *operator, const rule_t *rule){

	_meta_state_t *state = _create_new_state( 0 );
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
			_create_new_transition( FSM_EVENT_TIMEOUT, 0, s_final, NULL, NULL));

	//gen for context
	_gen_transition_rule( s_init, state, s_error, states_list, context, index, rule );
	//increase index
	state->index = (*index)++;
	states_list  = append_node_to_link_list( states_list, state );
	//gen for trigger
	_gen_transition_rule( state, s_error, s_final, states_list, trigger, index, rule );

	//create a new loop-itself
	if( context->type == RULE_EVENT ){
		state->exit_action = FSM_ACTION_CREATE_INSTANCE;
		state->transitions = append_node_to_link_list( state->transitions,
				_create_new_transition( FSM_EVENT, context->event->id, state, NULL, "Loop to create a new instance"));
	}
}

/**
 * Generate a fsm of a rule
 */
static inline void _gen_transition_rule( _meta_state_t *s_init,  _meta_state_t *s_final,  _meta_state_t *s_error,
		link_node_t *states_list, const  rule_node_t *rule_node, size_t *index, const rule_t *rule){

	rule_operator_t *opt;

	if( rule_node->type == RULE_EVENT ){

		s_init->transitions = append_node_to_link_list( s_init->transitions,
				_create_new_transition(FSM_EVENT, rule_node->event->id, s_final, rule_node->event, NULL ));
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
////////////////////////////////////////////////////////////////////////////////

static void _gen_fsm_state_for_a_rule( FILE *fd, const rule_t *rule ){
	size_t size, states_count, i;
	_meta_state_t *s_init, *s_error, *s_final, *state;
	_meta_transition_t *tran;
	link_node_t *states_list = NULL, *p_link_node, *p_t;
	char buffer[ MAX_STR_BUFFER ];

	uint32_t rule_id = rule->id;

	states_count = 0;
	s_init = _create_new_state( states_count ++ );
	s_error = _create_new_state( states_count ++ );
	s_final = _create_new_state( states_count ++ );

	sprintf(s_init->comment, "initial state");
	s_init->description = rule->description;

	sprintf(s_final->comment, "final state");
	//s_final->entry_action = rule->if_satisfied;

	sprintf( s_error->comment, "timeout/error state");
	//s_error->entry_action = rule->if_not_satisfied;

	states_list = append_node_to_link_list(states_list, s_init );
	states_list = append_node_to_link_list(states_list, s_error );
	states_list = append_node_to_link_list(states_list, s_final );

	_gen_transition_then(s_init, s_final, s_error, states_list, rule->context, rule->trigger, &states_count, NULL, rule);

	_gen_comment( fd, "States of FSM for rule %d", rule_id );
	_gen_comment(fd, "Predefine list of states: init, error, final, ..." );
	fprintf(fd, "static fsm_state_t");
	p_link_node = states_list;
	while( p_link_node != NULL ){
		state = (_meta_state_t *)p_link_node->data;
		fprintf( fd, " s_%d_%zu%c", rule_id, state->index, (p_link_node->next == NULL? ';':',') );

		p_link_node = p_link_node->next;
	}

	/**
	 * Print detail of each state
	 */
	_gen_comment(fd, "Initialize states: init, error, final, ..." );
	fprintf(fd, "static fsm_state_t");
	p_link_node = states_list;
	while( p_link_node != NULL ){
		state = (_meta_state_t *)p_link_node->data;
		if( strlen( state->comment ))
			_gen_comment(fd, "%s", state->comment );

		fprintf( fd, " s_%d_%zu = {", rule_id, state->index );
		fprintf( fd, "\n\t.timer        = 0,");
		fprintf( fd, "\n\t.counter      = 0,");
		fprintf( fd, "\n\t.delay        = {.time_min = %.2f, .time_max = %.2f, .counter_min = %d, .counter_max = %d},",
				state->delay?state->delay->time_min:0, state->delay?state->delay->time_max:0,
						state->delay?state->delay->counter_min:0, state->delay?state->delay->counter_max:0);

		fprintf( fd, "\n\t.description  = %c%s%c,", _string( state->description, ' ', "NULL", ' ', '"', state->description, '"'));
		fprintf( fd, "\n\t.entry_action = %d,", state->entry_action );
		fprintf( fd, "\n\t.exit_action  = %d,", state->exit_action  );

		size = 0;
		//print list of outgoing transitions of this state
		if( state->transitions == NULL ){
			fprintf( fd, "\n\t.transitions  = NULL,");
		}else{
			fprintf( fd, "\n\t.transitions  = (fsm_transition_t[]){");
			p_t = state->transitions;
			while( p_t != NULL ){
				size ++;
				tran = (_meta_transition_t *)p_t->data;
				if( tran->attached_event && tran->attached_event->description )
					fprintf( fd, "\n\t\t/** %d %s */", __LINE__, tran->attached_event->description );
				if( tran->comment[0] != '\0' )
					fprintf( fd, "\n\t\t/** %d %s */", __LINE__, tran->comment );
				sprintf( buffer, "&g_%d_%d", rule_id, tran->guard_id );
				fprintf( fd, "\n\t\t{ .event_type = %d, .condition = NULL, .guard = %s, .action = NULL, .target_state = &s_%d_%zu}%c",
						tran->event_type,
						(tran->event_type == FSM_EVENT_TIMEOUT ? "NULL  "  : buffer   ), //guard
						rule_id, tran->target->index, //target_state
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

	//create an array of pointers point to the states
	_gen_comment(fd, "Array to quickly access to a state by index");
	fprintf( fd, "static fsm_state_t* s_%d[%zu] = {", rule->id, states_count );
	p_link_node = states_list;
	while( p_link_node != NULL ){
		state = (_meta_state_t *)p_link_node->data;
		fprintf( fd, "&s_%d_%zu%s", rule->id, state->index, (p_link_node->next == NULL?"};":", ") );

		p_link_node = p_link_node->next;
	}

	_gen_comment(fd, "Create a new FSM for this rule");
	fprintf( fd, "void *mmt_sec_create_new_fsm_%d(){", rule->id);
	fprintf( fd, "\n\t\treturn fsm_init( &s_%d_0, &s_%d_1, &s_%d_2 );//init, error, final",
			rule->id, rule->id, rule->id );
	fprintf( fd, "\n}//end function");


	free_link_list( states_list, YES );
}

void _iterate_variables_to_print_switch( void *key, void *data, void *user_data, size_t index, size_t total){
	static uint32_t last_proto_id = -1;
	struct _user_data *_u_data = (struct _user_data *)user_data;
	FILE *fd         = _u_data->file;
	uint32_t rule_id = _u_data->index;

	variable_t *var = (variable_t *)data;

	//first element
	if( index == 0 ){
		last_proto_id = -1; //reset the static variable
		_gen_comment( fd, "Public API" );
		fprintf( fd, "void* mmt_sec_hash_message_%d( uint32_t proto_id, uint32_t att_id){", rule_id);
		fprintf( fd, "\n\tswitch( proto_id ){");
	}

	if( last_proto_id != var->proto_id ){
		if( index != 0 ){
			fprintf(fd, "\n\t\tdefault:\n\t\t\tfprintf(stderr, \"Do not find attribute %%d of protocol %d in the given rules.\", att_id);\n\t\t\texit(1);", last_proto_id );
			fprintf(fd, "\n\t\t}//end att for %d", last_proto_id ); //close the previous switch
		}
		_gen_comment( fd, "%s", var->proto );
		fprintf(fd, "\tcase %d:", var->proto_id );
		fprintf(fd, "\n\t\tswitch ( att_id){");
	}

	fprintf(fd, "\n\t\tcase %d:\t//%s", var->att_id, var->att );
	fprintf(fd, "\n\t\t\treturn NULL;//%zu;", index );

	if( index == total-1 ){
		fprintf(fd, "\n\t\tdefault:\n\t\t\tfprintf(stderr, \"Do not find attribute %%d of protocol %d in the given rules.\", att_id);\n\t\t\texit(1);", last_proto_id );
		fprintf(fd, "\n\t\t}//last switch");

		fprintf( fd, "\n\tdefault:\n\t\tfprintf(stderr, \"Do not find protocol %%d in the given rules.\", proto_id);\n\t\texit(1);");
		fprintf( fd, "\n\t}"); //end switch
		fprintf( fd, "\n}");//end function
	}

	last_proto_id = var->proto_id;
}

void _iterate_variables_to_gen_structure( void *key, void *data, void *user_data, size_t index, size_t total ){
	struct _user_data *_u_data = (struct _user_data *)user_data;
	FILE *fd = _u_data->file;
	variable_t *var = (variable_t *)data;
	//first element
	if( index == 0 ){
		_gen_comment( fd, "Structure to represent event data");
		fprintf( fd, "typedef struct _msg_struct_%d{", _u_data->index );
	}
	fprintf( fd, "\n\t %s%s_%s;",
			(var->data_type == NUMERIC? "double ":"const char *"),
			var->proto, var->att);

	//last element
	if( index + 1 == total ){
		fprintf( fd, "\n\t uint64_t timestamp;//timestamp");
		fprintf( fd, "\n\t uint64_t counter;//index of packet");
		fprintf( fd, "\n}_msg_t_%d;", _u_data->index );
	}
}

void _iterate_variables_to_convert_to_structure( void *key, void *data, void *user_data, size_t index, size_t total ){
	struct _user_data *_u_data = (struct _user_data *)user_data;
	FILE *fd = _u_data->file;
	uint32_t rule_id = _u_data->index;

	variable_t *var = (variable_t *)data;
	static uint32_t old_proto_id = -1;
	//first element
	if( index == 0 ){
		old_proto_id = -1; //init
		_gen_comment( fd, "Public API" );
		fprintf( fd, "void *mmt_sec_convert_message_to_event_%d( const message_t *msg){", rule_id );
		fprintf( fd, "\n\tif( msg == NULL ) return NULL;" );
		fprintf( fd, "\n\t_msg_t_%d *new_msg = mmt_malloc( sizeof( _msg_t_%d ));", rule_id, rule_id );
		fprintf( fd, "\n\tsize_t i;" );
		fprintf( fd, "\n\tnew_msg->timestamp = msg->timestamp;" );
		fprintf( fd, "\n\tnew_msg->counter = msg->counter;" );
		fprintf( fd, "\n\tfor( i=0; i<msg->elements_count; i++){" );

		fprintf( fd, "\n\t\tswitch( msg->elements[i]->proto_id ){" );
		_gen_comment_line( fd, "For each protocol");
	}

	//each time we change from one protocol to other
	if( old_proto_id != var->proto_id ){
		//not the first element
		if( index != 0 ){
			fprintf( fd, "\n\t\t\t}//end switch of att_id %d", __LINE__);
			fprintf( fd, "\n\t\t\tbreak;");
		}
		fprintf( fd, "\n\t\tcase %d:// protocol %s", var->proto_id, var->proto );
		fprintf( fd, "\n\t\t\tswitch( msg->elements[i]->att_id ){" );
	}

	//content of switch
	fprintf( fd, "\n\t\t\tcase %d:// attribute %s", var->att_id, var->att );
	if( var->data_type == NUMERIC )
		fprintf( fd, "\n\t\t\t\tnew_msg->%s_%s = *(double *)msg->elements[i]->data;",
			var->proto, var->att);
	else
		fprintf( fd, "\n\t\t\t\tnew_msg->%s_%s = mmt_mem_retain( msg->elements[i]->data );",
			var->proto, var->att);
	fprintf( fd, "\n\t\t\t\tbreak;");

	//last element
	if( index + 1 == total ){
		fprintf( fd, "\n\t\t\t}//end switch of att_id %d", __LINE__);
		fprintf( fd, "\n\t\t}//end switch");
		fprintf( fd, "\n\t}//end for");
		fprintf( fd, "\n\treturn (void *)new_msg; //%d", __LINE__);
		fprintf( fd, "\n}//end function");
	}

	old_proto_id = var->proto_id;
}
/**
 * Generate general informations of rules
 */
static inline void _gen_rule_information( FILE *fd, rule_t *const* rules, size_t count ){
	size_t i;

	fprintf(fd, "\n\n//======================================GENERAL======================================");
	_gen_comment( fd, "Information of %zu rules", count );
	fprintf( fd, "size_t mmt_sec_get_plugin_info( const rule_info_t **rules_arr ){");
	fprintf( fd, "\n\t static const rule_info_t rules[] = (rule_info_t[]){");
	for( i=0; i<count; i++ ){
		fprintf( fd, "\n\t\t{");
		fprintf( fd, "\n\t\t\t.id               = %d,", rules[i]->id );
		fprintf( fd, "\n\t\t\t.description      = %c%s%c,",
						_string( rules[i]->description, 'N', "UL", 'L', '"', rules[i]->description, '"') );
		fprintf( fd, "\n\t\t\t.if_satisfied     = %c%s%c,",
				_string( rules[i]->if_satisfied, 'N', "UL", 'L', '"', rules[i]->if_satisfied, '"') );
		fprintf( fd, "\n\t\t\t.if_not_satisfied = %c%s%c,",
				_string( rules[i]->if_not_satisfied, 'N', "UL", 'L', '"', rules[i]->if_not_satisfied, '"') );
		fprintf( fd, "\n\t\t\t.create_instance  = &mmt_sec_create_new_fsm_%d,", rules[i]->id );
		fprintf( fd, "\n\t\t\t.hash_message     = NULL,//&mmt_sec_hash_message_%d,", rules[i]->id );
		fprintf( fd, "\n\t\t\t.convert_message  = &mmt_sec_convert_message_to_event_%d", rules[i]->id );

		if( i < count -1 )
			fprintf( fd, "\n\t\t},");
		else
			fprintf( fd, "\n\t\t}");
	}
	fprintf( fd, "\n\t};\n\t*rules_arr = rules;");
	fprintf( fd, "\n\treturn %zu;\n}", count);
}


void _iterate_variable_to_add_to_a_new_map( void *key, void *data, void *user_data, size_t index, size_t total ){
	mmt_map_set_data((mmt_map_t *)user_data, data, data, NO );
}
void _iterate_event_to_get_unique_variables( void *key, void *data, void *user_data, size_t index, size_t total ){
	rule_event_t *ev = (rule_event_t *)data;
	mmt_map_t *map;
	get_unique_variables_of_expression( ev->expression, &map, NO );
	mmt_map_iterate( map, _iterate_variable_to_add_to_a_new_map, user_data );
	mmt_map_free( map, NO );
}

static void _gen_fsm_for_a_rule( FILE *fd, const rule_t *rule ){
	char *str_ptr;
	size_t i, size;
	struct _user_data _u_data;
	_u_data.file  = fd;
	_u_data.index = rule->id;
	/**
	 * a set of events
	 * <event_id, map>
	 */
	mmt_map_t *events_map = NULL;
	/**
	 * a set of unique variables
	 * <variable,variable>
	 */
	mmt_map_t *variables_map =  mmt_map_init( &compare_variable_name );

	size = get_unique_events_of_rule( rule, &events_map );
	if( size == 0 ) return;


	fprintf(fd, "\n\n//======================================RULE %d======================================", rule->id );

	mmt_map_iterate( events_map, _iterate_event_to_get_unique_variables, variables_map );

	//define a structure using in guard functions
	mmt_map_iterate(variables_map, _iterate_variables_to_gen_structure, &_u_data );
	//convert from a message_t to a structure generated above
	mmt_map_iterate(variables_map, _iterate_variables_to_convert_to_structure, &_u_data );

	mmt_map_iterate(variables_map, _iterate_variables_to_print_switch, &_u_data );

	mmt_map_iterate(events_map, _iterate_event_to_gen_guards, &_u_data );


	_gen_fsm_state_for_a_rule( fd, rule );

	//free mmt_map
	mmt_map_free( events_map, NO );
	mmt_map_free( variables_map, NO );
}

/**
 * Public API
 */
int generate_fsm( const char* file_name, rule_t *const* rules, size_t count ){
	char *str_ptr;
	size_t i;
	//open file for writing
	FILE *fd = fopen(file_name, "w");
	mmt_assert (fd != NULL, "Error 11a: Cannot open file %s for writing", file_name );

	str_ptr = get_current_date_time_string( "%Y-%m-%d %H:%M:%S" );
	_gen_comment( fd, "This file is generated automatically on %s", str_ptr);
	mmt_free( str_ptr );

	//include
	fprintf( fd, "#include <string.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include \"plugin_header.h\"\n#include \"mmt_fsm.h\"\n#include \"mmt_alloc.h\"\n");

	for( i=0; i<count; i++ )
		_gen_fsm_for_a_rule( fd, rules[i] );

	//information of rules
	_gen_rule_information( fd, rules, count );

	fclose(fd);

	return 0;
}

/**
 * Compile the generated code
 */
int compile_gen_code( const char *lib_file, const char *code_file ){
	char cmd_str[ 10000 ];
	sprintf( cmd_str, "/usr/bin/gcc -fPIC -shared %s -o %s -I /home/mmt/mmt-security/src/lib", code_file, lib_file );
	return system ( cmd_str );
}
