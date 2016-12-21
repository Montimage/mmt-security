
 /** 920
  * This file is generated automatically on 2016-12-21 10:25:47
  */
 #include <string.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include "plugin_header.h"
 #include "mmt_fsm.h"
 #include "mmt_lib.h"
 
 /** 927
  * Embedded functions
  */
 

 //======================================RULE 2======================================
 #define EVENTS_COUNT_2 3

 #define PROTO_ATTS_COUNT_2 5

 /** 866
  * Proto_atts for rule 2
  */
 
 static proto_attribute_t proto_atts_2[ PROTO_ATTS_COUNT_2 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "dest_port", .att_id = 2, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "flags", .att_id = 6, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "src_port", .att_id = 1, .data_type = 0}};
 /** 875
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_2[ 4 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_2[ 0 ] ,  &proto_atts_2[ 1 ] ,  &proto_atts_2[ 2 ] ,  &proto_atts_2[ 3 ] }
	 },
	 {//event_2
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_2[ 4 ] ,  &proto_atts_2[ 5 ] ,  &proto_atts_2[ 6 ] ,  &proto_atts_2[ 7 ] }
	 },
	 {//event_3
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_2[ 8 ] ,  &proto_atts_2[ 9 ] ,  &proto_atts_2[ 10 ] ,  &proto_atts_2[ 11 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_2{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const char *ip_src;
	 const double *tcp_dest_port;
	 const double *tcp_flags;
	 const double *tcp_src_port;
 }_msg_t_2;
 /** 592
  * Create an instance of _msg_t_2
  */
 static inline _msg_t_2* _allocate_msg_t_2(){
	 _msg_t_2 *m = mmt_mem_alloc( sizeof( _msg_t_2 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_dest_port = NULL;
	 m->tcp_flags = NULL;
	 m->tcp_src_port = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_2( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_2 *new_msg = _allocate_msg_t_2();
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i].proto_id ){/** 626 For each protocol*/
		 case 178:// protocol ip
			 switch( msg->elements[i].att_id ){
			 case 13:// attribute dst
				 new_msg->ip_dst = (char *) msg->elements[i].data;
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 633
			 break;
		 case 354:// protocol tcp
			 switch( msg->elements[i].att_id ){
			 case 2:// attribute dest_port
				 new_msg->tcp_dest_port = (double *) msg->elements[i].data;
				 break;
			 case 6:// attribute flags
				 new_msg->tcp_flags = (double *) msg->elements[i].data;
				 break;
			 case 1:// attribute src_port
				 new_msg->tcp_src_port = (double *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_2( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_2 ];
	 size_t i;	 _msg_t_2 *msg = (_msg_t_2 *) data;
	 for( i=0; i<EVENTS_COUNT_2; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_dest_port != NULL && msg->tcp_flags != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_flags != NULL && msg->tcp_src_port != NULL )
		 hash_table[ 1 ] = 2;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_dest_port != NULL && msg->tcp_flags != NULL )
		 hash_table[ 2 ] = 3;
	 return hash_table;
 }
 /** 94
  * Rule 2, event 1
  * SYN request
  */
 static inline int g_2_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_2 *his_data, *ev_data = (_msg_t_2 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->tcp_dest_port == NULL )) return 0;
	 double tcp_dest_port = *( ev_data->tcp_dest_port );/* 61 */
	 if( unlikely( ev_data->tcp_flags == NULL )) return 0;
	 double tcp_flags = *( ev_data->tcp_flags );

	 return ((tcp_flags == 2) && ((tcp_dest_port == 22) && 0 != strcmp(ip_src , ip_dst)));
 }
 
 /** 94
  * Rule 2, event 2
  * SYN ACK reply
  */
 static inline int g_2_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_2 *his_data, *ev_data = (_msg_t_2 *) event_data;
	 his_data = (_msg_t_2 *)fsm_get_history( fsm, 1);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_dst == NULL )) return 0;
	 const char *ip_dst_1 =  his_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( his_data->ip_src == NULL )) return 0;
	 const char *ip_src_1 =  his_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->tcp_flags == NULL )) return 0;
	 double tcp_flags = *( ev_data->tcp_flags );/* 61 */
	 if( unlikely( ev_data->tcp_src_port == NULL )) return 0;
	 double tcp_src_port = *( ev_data->tcp_src_port );

	 return ((tcp_flags == 18) && ((tcp_src_port == 22) && (0 == strcmp(ip_dst , ip_src_1) && 0 == strcmp(ip_src , ip_dst_1))));
 }
 
 /** 94
  * Rule 2, event 3
  * RST reset
  */
 static inline int g_2_3( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_2 *his_data, *ev_data = (_msg_t_2 *) event_data;
	 his_data = (_msg_t_2 *)fsm_get_history( fsm, 1);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_dst == NULL )) return 0;
	 const char *ip_dst_1 =  his_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( his_data->ip_src == NULL )) return 0;
	 const char *ip_src_1 =  his_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->tcp_dest_port == NULL )) return 0;
	 double tcp_dest_port = *( ev_data->tcp_dest_port );/* 61 */
	 if( unlikely( ev_data->tcp_flags == NULL )) return 0;
	 double tcp_flags = *( ev_data->tcp_flags );

	 return ((tcp_flags == 4) && ((tcp_dest_port == 22) && (0 == strcmp(ip_dst , ip_dst_1) && 0 == strcmp(ip_src , ip_src_1))));
 }
 
 /** 407
  * States of FSM for rule 2
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_2_0, s_2_1, s_2_2, s_2_3, s_2_4, s_2_5;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_2_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "Attempted to connect via ssh but reseted immediately. Source address is either infected machine or attacker (no spoofing is possible).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 SYN request */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_2_1, .action = 1, .target_state = &s_2_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_2_1 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 427
  * final state
  */
  s_2_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_2_3 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_2_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 1000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_2_3}, //FSM_ACTION_DO_NOTHING
		 /** 456 SYN ACK reply */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_2_2, .action = 1, .target_state = &s_2_5}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 2
 },
 /** 427
  * root node
  */
  s_2_5 = {
	 .delay        = {.time_min = 1LL, .time_max = 500000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  = "Attempted to connect via ssh but reseted immediately. Source address is either infected machine or attacker (no spoofing is possible).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_2_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 RST reset */
		 /** 458 A real event */
		 { .event_type = 3, .guard = &g_2_3, .action = 0, .target_state = &s_2_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_2(){
		 return fsm_init( &s_2_0, &s_2_1, &s_2_2, &s_2_3, EVENTS_COUNT_2 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================GENERAL======================================
 /** 666
  * Information of 1 rules
  */
 size_t mmt_sec_get_plugin_info( const rule_info_t **rules_arr ){
	  static const rule_info_t rules[] = (rule_info_t[]){
		 {
			 .id               = 2,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_2,
			 .proto_atts_count = PROTO_ATTS_COUNT_2,
			 .proto_atts       = proto_atts_2,
			 .proto_atts_events= proto_atts_events_2,
			 .description      = "Attempted to connect via ssh but reseted immediately. Source address is either infected machine or attacker (no spoofing is possible).",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_2,
			 .hash_message     = &hash_message_2,
			 .convert_message  = &convert_message_to_event_2
		 }
	 };
	 *rules_arr = rules;
	 return 1;
 }
 /** 696
  * Moment the rules being encoded
  */
 
 const char * __get_generated_date(){ return "2016-12-21 10:25:47, version 1.0.0 (e9dc6f2)";};