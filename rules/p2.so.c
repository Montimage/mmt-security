
 /** 927
  * This file is generated automatically on 2017-01-31 14:13:20
  */
 #include <string.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include "plugin_header.h"
 #include "mmt_fsm.h"
 #include "mmt_lib.h"
 
 /** 934
  * Embedded functions
  */
 

 //======================================RULE 1======================================
 #define EVENTS_COUNT_1 2

 #define PROTO_ATTS_COUNT_1 4

 /** 867
  * Proto_atts for rule 1
  */
 
 static proto_attribute_t proto_atts_1[ PROTO_ATTS_COUNT_1 ] = {{.proto = "http", .proto_id = 153, .att = "method", .att_id = 1, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "dest_port", .att_id = 2, .data_type = 0}};
 /** 879
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_1[ 3 ] = { {.elements_count = 0, .data = NULL},
	 {//event_1
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_1[ 0 ] ,  &proto_atts_1[ 3 ] }
	 },
	 {//event_2
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_1[ 1 ] ,  &proto_atts_1[ 2 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_1{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *http_method;
	 const char *ip_dst;
	 const char *ip_src;
	 const double *tcp_dest_port;
 }_msg_t_1;
 /** 592
  * Create an instance of _msg_t_1
  */
 static inline _msg_t_1* _allocate_msg_t_1(){
	 static _msg_t_1 _msg;
	 _msg_t_1 *m = &_msg;
	 m->http_method = NULL;
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_dest_port = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 617
  * Public API
  */
 static const void *convert_message_to_event_1( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_1 *new_msg = _allocate_msg_t_1();
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i].proto_id ){/** 627 For each protocol*/
		 case 153:// protocol http
			 switch( msg->elements[i].att_id ){
			 case 1:// attribute method
				 new_msg->http_method = (char *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 634
			 break;
		 case 178:// protocol ip
			 switch( msg->elements[i].att_id ){
			 case 13:// attribute dst
				 new_msg->ip_dst = (char *) msg->elements[i].data;
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 634
			 break;
		 case 354:// protocol tcp
			 switch( msg->elements[i].att_id ){
			 case 2:// attribute dest_port
				 new_msg->tcp_dest_port = (double *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 651
		 }//end switch
	 }//end for
	 return (void *)new_msg; //654
 }//end function
 /** 523
  * Public API
  */
 static uint64_t hash_message_1( const void *data ){
	 uint64_t hash = 0;
	 size_t i;	 _msg_t_1 *msg = (_msg_t_1 *) data;
	 //if( msg == NULL ) return hash;

	 if( msg->http_method != NULL && msg->tcp_dest_port != NULL )
		 hash  |= 2; //event_id = 1
	 if( msg->ip_dst != NULL && msg->ip_src != NULL )
		 hash  |= 4; //event_id = 2
	 return hash;
 }
 /** 94
  * Rule 1, event 1
  * HTTP packet using a port different from 80 and 8080
  */
 static inline int g_1_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_1 *his_data, *ev_data = (_msg_t_1 *) event_data;/* 61 */
	 if( unlikely( ev_data->http_method == NULL )) return 0;
	 const char *http_method =  ev_data->http_method ;/* 61 */
	 if( unlikely( ev_data->tcp_dest_port == NULL )) return 0;
	 double tcp_dest_port = *( ev_data->tcp_dest_port );

	 return ((strcmp(http_method , "")) && ((tcp_dest_port != 80) && (tcp_dest_port != 8080)));
 }
 
 /** 94
  * Rule 1, event 2
  * HTTP packet
  */
 static inline int g_1_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_1 *his_data, *ev_data = (_msg_t_1 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return 0 != mmt_mem_cmp(ip_src , ip_dst);
 }
 
 /** 411
  * States of FSM for rule 1
  */
 
 /** 412
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_1_0, s_1_1, s_1_2, s_1_3, s_1_4;
 /** 425
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 431
  * initial state
  */
  s_1_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "C4_Analyse_03f : HTTP using a port different from 80 and 8080.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 460 HTTP packet using a port different from 80 and 8080 */
		 /** 462 A real event */
		 { .event_type = 1, .guard = &g_1_1, .action = 1, .target_state = &s_1_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 431
  * timeout/error state
  */
  s_1_1 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 431
  * pass state
  */
  s_1_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 431
  * inconclusive state
  */
  s_1_3 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 431
  * root node
  */
  s_1_4 = {
	 .delay        = {.time_min = 0LL, .time_max = 0LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 1,
	 .description  = "C4_Analyse_03f : HTTP using a port different from 80 and 8080.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 462 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_1_1}, //FSM_ACTION_DO_NOTHING
		 /** 460 HTTP packet */
		 /** 462 A real event */
		 { .event_type = 2, .guard = &g_1_2, .action = 2, .target_state = &s_1_2}  //FSM_ACTION_RESET_TIMER
	 },
	 .transitions_count = 2
 };
 /** 489
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_1(){
		 return fsm_init( &s_1_0, &s_1_1, &s_1_2, &s_1_3, EVENTS_COUNT_1 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================GENERAL======================================
 /** 667
  * Information of 1 rules
  * PUBLIC API
  */
 size_t mmt_sec_get_plugin_info( const rule_info_t **rules_arr ){
	  static const rule_info_t rules[] = (rule_info_t[]){
		 {
			 .id               = 1,
			 .type_id          = 2,
			 .type_string      = "evasion",
			 .events_count     = EVENTS_COUNT_1,
			 .proto_atts_count = PROTO_ATTS_COUNT_1,
			 .proto_atts       = proto_atts_1,
			 .proto_atts_events= proto_atts_events_1,
			 .description      = "C4_Analyse_03f : HTTP using a port different from 80 and 8080.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_1,
			 .hash_message     = &hash_message_1,
			 .convert_message  = &convert_message_to_event_1,
			 .message_size     = sizeof( _msg_t_1 )
		 }
	 };
	 *rules_arr = rules;
	 return 1;
 }
 /** 697
  * Moment the rules being encoded
  * PUBLIC API
  */
 const char * __get_generated_date(){ return "2017-01-31 14:13:20, mmt-security version 1.0.0 (af1e5ee)";};
