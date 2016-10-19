
 /** 695
  * This file is generated automatically on 2016-10-19 16:55:50
  */
 #include <string.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include "plugin_header.h"
 #include "mmt_fsm.h"
 #include "mmt_alloc.h"
 

 //======================================RULE 1======================================
 #define EVENTS_COUNT_1 4

 #define PROTO_ATTS_COUNT_1 5

 static proto_attribute_t proto_atts_1[ PROTO_ATTS_COUNT_1 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "dest_port", .att_id = 2, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "flags", .att_id = 6, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "src_port", .att_id = 1, .data_type = 0}};

 /** 484
  * Structure to represent event data
  */
 typedef struct _msg_struct_1{
	  const char *ip_dst;
	  const char *ip_src;
	  const double *tcp_dest_port;
	  const double *tcp_flags;
	  const double *tcp_src_port;
	  uint64_t timestamp;//timestamp
	  uint64_t counter;//index of packet
 }_msg_t_1;
 /** 519
  * Create an instance of _msg_t_1
  */
 static inline _msg_t_1* _allocate_msg_t_1(){
	 _msg_t_1 *m = mmt_malloc( sizeof( _msg_t_1 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_dest_port = NULL;
	 m->tcp_flags = NULL;
	 m->tcp_src_port = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 543
  * Public API
  */
 static void *convert_message_to_event_1( const message_t *msg){
	 if( msg == NULL ) return NULL;
	 _msg_t_1 *new_msg = _allocate_msg_t_1( sizeof( _msg_t_1 ));
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i].proto_id ){/** 553 For each protocol*/
		 case 178:// protocol ip
			 switch( msg->elements[i].att_id ){
			 case 13:// attribute dst
				 new_msg->ip_dst = (char *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 }//end switch of att_id 560
			 break;
		 case 354:// protocol tcp
			 switch( msg->elements[i].att_id ){
			 case 2:// attribute dest_port
				 new_msg->tcp_dest_port = (double *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 case 6:// attribute flags
				 new_msg->tcp_flags = (double *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 case 1:// attribute src_port
				 new_msg->tcp_src_port = (double *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 }//end switch of att_id 577
		 }//end switch
	 }//end for
	 return (void *)new_msg; //580
 }//end function
 /** 449
  * Public API
  */
 static const uint16_t* hash_message_1( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_1 ];
	 size_t i;	 _msg_t_1 *msg = (_msg_t_1 *) data;
	 for( i=0; i<EVENTS_COUNT_1; i++) hash_table[i] = 0;/** 455 Rest hash_table. This is call for every executions*/
	 if( msg == NULL ) return hash_table;
	 if( msg->tcp_dest_port != NULL && msg->tcp_flags != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_flags != NULL && msg->tcp_src_port != NULL )
		 hash_table[ 1 ] = 2;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_dest_port != NULL && msg->tcp_flags != NULL )
		 hash_table[ 2 ] = 3;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_flags != NULL && msg->tcp_src_port != NULL )
		 hash_table[ 3 ] = 4;
	 return hash_table;
 }
 /** 91
  * Rule 1, event 1
  * SYN request
  */
 static inline int g_1_1( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_1 *his_data, *ev_data = (_msg_t_1 *) event_data;
	 if( ev_data->tcp_dest_port == NULL ) return 0;/* 62 */
	 double tcp_dest_port = *( ev_data->tcp_dest_port );
	 if( ev_data->tcp_flags == NULL ) return 0;/* 62 */
	 double tcp_flags = *( ev_data->tcp_flags );

	 return ((tcp_flags == 2) && (tcp_dest_port == 22));
 }
 
 /** 91
  * Rule 1, event 2
  * SYN ACK reply
  */
 static inline int g_1_2( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_1 *his_data, *ev_data = (_msg_t_1 *) event_data;
	 his_data = (_msg_t_1 *)fsm_get_history( fsm, 1);
	 if( his_data == NULL ) return 0;
	 if( his_data->ip_dst == NULL ) return 0;/* 62 */
	 const char *ip_dst_1 =  his_data->ip_dst ;
	 if( ev_data->ip_dst == NULL ) return 0;/* 62 */
	 const char *ip_dst =  ev_data->ip_dst ;
	 his_data = (_msg_t_1 *)fsm_get_history( fsm, 1);
	 if( his_data == NULL ) return 0;
	 if( his_data->ip_src == NULL ) return 0;/* 62 */
	 const char *ip_src_1 =  his_data->ip_src ;
	 if( ev_data->ip_src == NULL ) return 0;/* 62 */
	 const char *ip_src =  ev_data->ip_src ;
	 if( ev_data->tcp_flags == NULL ) return 0;/* 62 */
	 double tcp_flags = *( ev_data->tcp_flags );
	 if( ev_data->tcp_src_port == NULL ) return 0;/* 62 */
	 double tcp_src_port = *( ev_data->tcp_src_port );

	 return ((tcp_flags == 18) && ((tcp_src_port == 22) && (0 == strcmp(ip_dst , ip_src_1) && 0 == strcmp(ip_src , ip_dst_1))));
 }
 
 /** 91
  * Rule 1, event 3
  * SYN request
  */
 static inline int g_1_3( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_1 *his_data, *ev_data = (_msg_t_1 *) event_data;
	 his_data = (_msg_t_1 *)fsm_get_history( fsm, 1);
	 if( his_data == NULL ) return 0;
	 if( his_data->ip_dst == NULL ) return 0;/* 62 */
	 const char *ip_dst_1 =  his_data->ip_dst ;
	 if( ev_data->ip_dst == NULL ) return 0;/* 62 */
	 const char *ip_dst =  ev_data->ip_dst ;
	 his_data = (_msg_t_1 *)fsm_get_history( fsm, 1);
	 if( his_data == NULL ) return 0;
	 if( his_data->ip_src == NULL ) return 0;/* 62 */
	 const char *ip_src_1 =  his_data->ip_src ;
	 if( ev_data->ip_src == NULL ) return 0;/* 62 */
	 const char *ip_src =  ev_data->ip_src ;
	 if( ev_data->tcp_dest_port == NULL ) return 0;/* 62 */
	 double tcp_dest_port = *( ev_data->tcp_dest_port );
	 if( ev_data->tcp_flags == NULL ) return 0;/* 62 */
	 double tcp_flags = *( ev_data->tcp_flags );

	 return ((tcp_flags == 2) && ((tcp_dest_port == 22) && (0 == strcmp(ip_src , ip_src_1) && 0 == strcmp(ip_dst , ip_dst_1))));
 }
 
 /** 91
  * Rule 1, event 4
  * SYN ACK reply
  */
 static inline int g_1_4( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_1 *his_data, *ev_data = (_msg_t_1 *) event_data;
	 his_data = (_msg_t_1 *)fsm_get_history( fsm, 1);
	 if( his_data == NULL ) return 0;
	 if( his_data->ip_dst == NULL ) return 0;/* 62 */
	 const char *ip_dst_1 =  his_data->ip_dst ;
	 if( ev_data->ip_dst == NULL ) return 0;/* 62 */
	 const char *ip_dst =  ev_data->ip_dst ;
	 his_data = (_msg_t_1 *)fsm_get_history( fsm, 1);
	 if( his_data == NULL ) return 0;
	 if( his_data->ip_src == NULL ) return 0;/* 62 */
	 const char *ip_src_1 =  his_data->ip_src ;
	 if( ev_data->ip_src == NULL ) return 0;/* 62 */
	 const char *ip_src =  ev_data->ip_src ;
	 if( ev_data->tcp_flags == NULL ) return 0;/* 62 */
	 double tcp_flags = *( ev_data->tcp_flags );
	 if( ev_data->tcp_src_port == NULL ) return 0;/* 62 */
	 double tcp_src_port = *( ev_data->tcp_src_port );

	 return ((tcp_flags == 18) && ((tcp_src_port == 22) && (0 == strcmp(ip_dst , ip_src_1) && 0 == strcmp(ip_src , ip_dst_1))));
 }
 
 /** 340
  * States of FSM for rule 1
  */
 
 /** 341
  * Predefine list of states: init, error, final, ...
  */
 static fsm_state_t s_1_0, s_1_1, s_1_2, s_1_3, s_1_4, s_1_5;
 /** 354
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 360
  * initial state
  */
  s_1_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  = "Several attempts to connect via ssh (brute force attack). Source address is either infected machine or attacker (no spoofing is possible).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 382 SYN request */
		 /** 384 A real event */
		 { .event_type = 1, .guard = &g_1_1, .target_state = &s_1_3} 
	 },
	 .transitions_count = 1
 },
 /** 360
  * timeout/error state
  */
  s_1_1 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 360
  * final state
  */
  s_1_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_1_3 = {
	 .delay        = {.time_min = 0, .time_max = 1000000, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 384 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .target_state = &s_1_4},
		 /** 382 SYN ACK reply */
		 /** 384 A real event */
		 { .event_type = 2, .guard = &g_1_2, .target_state = &s_1_4},
		 /** 384 A real event will fire this loop to create a new instance */
		 { .event_type = 1, .guard = &g_1_1, .target_state = &s_1_3} 
	 },
	 .transitions_count = 3
 },
 /** 360
  * root node
  */
  s_1_4 = {
	 .delay        = {.time_min = 0, .time_max = 60000000, .counter_min = 0, .counter_max = 0},
	 .description  = "Several attempts to connect via ssh (brute force attack). Source address is either infected machine or attacker (no spoofing is possible).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 384 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .target_state = &s_1_2},
		 /** 382 SYN request */
		 /** 384 A real event */
		 { .event_type = 3, .guard = &g_1_3, .target_state = &s_1_5} 
	 },
	 .transitions_count = 2
 }, s_1_5 = {
	 .delay        = {.time_min = 0, .time_max = 1000000, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 384 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .target_state = &s_1_1},
		 /** 382 SYN ACK reply */
		 /** 384 A real event */
		 { .event_type = 4, .guard = &g_1_4, .target_state = &s_1_2},
		 /** 384 A real event will fire this loop to create a new instance */
		 { .event_type = 3, .guard = &g_1_3, .target_state = &s_1_5} 
	 },
	 .transitions_count = 3
 };
 /** 417
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_1(){
		 return fsm_init( &s_1_0, &s_1_1, &s_1_2 );//init, error, final
 }//end function

 //======================================RULE 2======================================
 #define EVENTS_COUNT_2 3

 #define PROTO_ATTS_COUNT_2 5

 static proto_attribute_t proto_atts_2[ PROTO_ATTS_COUNT_2 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "dest_port", .att_id = 2, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "flags", .att_id = 6, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "src_port", .att_id = 1, .data_type = 0}};

 /** 484
  * Structure to represent event data
  */
 typedef struct _msg_struct_2{
	  const char *ip_dst;
	  const char *ip_src;
	  const double *tcp_dest_port;
	  const double *tcp_flags;
	  const double *tcp_src_port;
	  uint64_t timestamp;//timestamp
	  uint64_t counter;//index of packet
 }_msg_t_2;
 /** 519
  * Create an instance of _msg_t_2
  */
 static inline _msg_t_2* _allocate_msg_t_2(){
	 _msg_t_2 *m = mmt_malloc( sizeof( _msg_t_2 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_dest_port = NULL;
	 m->tcp_flags = NULL;
	 m->tcp_src_port = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 543
  * Public API
  */
 static void *convert_message_to_event_2( const message_t *msg){
	 if( msg == NULL ) return NULL;
	 _msg_t_2 *new_msg = _allocate_msg_t_2( sizeof( _msg_t_2 ));
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i].proto_id ){/** 553 For each protocol*/
		 case 178:// protocol ip
			 switch( msg->elements[i].att_id ){
			 case 13:// attribute dst
				 new_msg->ip_dst = (char *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 }//end switch of att_id 560
			 break;
		 case 354:// protocol tcp
			 switch( msg->elements[i].att_id ){
			 case 2:// attribute dest_port
				 new_msg->tcp_dest_port = (double *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 case 6:// attribute flags
				 new_msg->tcp_flags = (double *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 case 1:// attribute src_port
				 new_msg->tcp_src_port = (double *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 }//end switch of att_id 577
		 }//end switch
	 }//end for
	 return (void *)new_msg; //580
 }//end function
 /** 449
  * Public API
  */
 static const uint16_t* hash_message_2( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_2 ];
	 size_t i;	 _msg_t_2 *msg = (_msg_t_2 *) data;
	 for( i=0; i<EVENTS_COUNT_2; i++) hash_table[i] = 0;/** 455 Rest hash_table. This is call for every executions*/
	 if( msg == NULL ) return hash_table;
	 if( msg->tcp_dest_port != NULL && msg->tcp_flags != NULL )
		 hash_table[ 0 ] = 5;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_flags != NULL && msg->tcp_src_port != NULL )
		 hash_table[ 1 ] = 6;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_dest_port != NULL && msg->tcp_flags != NULL )
		 hash_table[ 2 ] = 7;
	 return hash_table;
 }
 /** 91
  * Rule 2, event 5
  * SYN request
  */
 static inline int g_2_5( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_2 *his_data, *ev_data = (_msg_t_2 *) event_data;
	 if( ev_data->tcp_dest_port == NULL ) return 0;/* 62 */
	 double tcp_dest_port = *( ev_data->tcp_dest_port );
	 if( ev_data->tcp_flags == NULL ) return 0;/* 62 */
	 double tcp_flags = *( ev_data->tcp_flags );

	 return ((tcp_flags == 2) && (tcp_dest_port == 22));
 }
 
 /** 91
  * Rule 2, event 6
  * SYN ACK reply
  */
 static inline int g_2_6( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_2 *his_data, *ev_data = (_msg_t_2 *) event_data;
	 his_data = (_msg_t_2 *)fsm_get_history( fsm, 5);
	 if( his_data == NULL ) return 0;
	 if( his_data->ip_dst == NULL ) return 0;/* 62 */
	 const char *ip_dst_5 =  his_data->ip_dst ;
	 if( ev_data->ip_dst == NULL ) return 0;/* 62 */
	 const char *ip_dst =  ev_data->ip_dst ;
	 his_data = (_msg_t_2 *)fsm_get_history( fsm, 5);
	 if( his_data == NULL ) return 0;
	 if( his_data->ip_src == NULL ) return 0;/* 62 */
	 const char *ip_src_5 =  his_data->ip_src ;
	 if( ev_data->ip_src == NULL ) return 0;/* 62 */
	 const char *ip_src =  ev_data->ip_src ;
	 if( ev_data->tcp_flags == NULL ) return 0;/* 62 */
	 double tcp_flags = *( ev_data->tcp_flags );
	 if( ev_data->tcp_src_port == NULL ) return 0;/* 62 */
	 double tcp_src_port = *( ev_data->tcp_src_port );

	 return ((tcp_flags == 18) && ((tcp_src_port == 22) && (0 == strcmp(ip_dst , ip_src_5) && 0 == strcmp(ip_src , ip_dst_5))));
 }
 
 /** 91
  * Rule 2, event 7
  * RST reset
  */
 static inline int g_2_7( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_2 *his_data, *ev_data = (_msg_t_2 *) event_data;
	 his_data = (_msg_t_2 *)fsm_get_history( fsm, 5);
	 if( his_data == NULL ) return 0;
	 if( his_data->ip_dst == NULL ) return 0;/* 62 */
	 const char *ip_dst_5 =  his_data->ip_dst ;
	 if( ev_data->ip_dst == NULL ) return 0;/* 62 */
	 const char *ip_dst =  ev_data->ip_dst ;
	 his_data = (_msg_t_2 *)fsm_get_history( fsm, 5);
	 if( his_data == NULL ) return 0;
	 if( his_data->ip_src == NULL ) return 0;/* 62 */
	 const char *ip_src_5 =  his_data->ip_src ;
	 if( ev_data->ip_src == NULL ) return 0;/* 62 */
	 const char *ip_src =  ev_data->ip_src ;
	 if( ev_data->tcp_dest_port == NULL ) return 0;/* 62 */
	 double tcp_dest_port = *( ev_data->tcp_dest_port );
	 if( ev_data->tcp_flags == NULL ) return 0;/* 62 */
	 double tcp_flags = *( ev_data->tcp_flags );

	 return ((tcp_flags == 4) && ((tcp_dest_port == 22) && (0 == strcmp(ip_dst , ip_dst_5) && 0 == strcmp(ip_src , ip_src_5))));
 }
 
 /** 340
  * States of FSM for rule 2
  */
 
 /** 341
  * Predefine list of states: init, error, final, ...
  */
 static fsm_state_t s_2_0, s_2_1, s_2_2, s_2_3, s_2_4, s_2_5;
 /** 354
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 360
  * initial state
  */
  s_2_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  = "Attempted to connect via ssh but reseted immediately. Source address is either infected machine or attacker (no spoofing is possible).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 382 SYN request */
		 /** 384 A real event */
		 { .event_type = 5, .guard = &g_2_5, .target_state = &s_2_3},
		 /** 382 SYN ACK reply */
		 /** 384 A real event */
		 { .event_type = 6, .guard = &g_2_6, .target_state = &s_2_4} 
	 },
	 .transitions_count = 2
 },
 /** 360
  * timeout/error state
  */
  s_2_1 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 360
  * final state
  */
  s_2_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_2_3 = {
	 .delay        = {.time_min = 0, .time_max = 1000000, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 384 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .target_state = &s_2_5},
		 /** 382 SYN ACK reply */
		 /** 384 A real event */
		 { .event_type = 6, .guard = &g_2_6, .target_state = &s_2_5},
		 /** 384 A real event will fire this loop to create a new instance */
		 { .event_type = 5, .guard = &g_2_5, .target_state = &s_2_3} 
	 },
	 .transitions_count = 3
 }, s_2_4 = {
	 .delay        = {.time_min = 0, .time_max = 1000000, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 384 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .target_state = &s_2_5},
		 /** 382 SYN request */
		 /** 384 A real event */
		 { .event_type = 5, .guard = &g_2_5, .target_state = &s_2_5},
		 /** 384 A real event will fire this loop to create a new instance */
		 { .event_type = 6, .guard = &g_2_6, .target_state = &s_2_4} 
	 },
	 .transitions_count = 3
 },
 /** 360
  * root node
  */
  s_2_5 = {
	 .delay        = {.time_min = 0, .time_max = 244000, .counter_min = 0, .counter_max = 0},
	 .description  = "Attempted to connect via ssh but reseted immediately. Source address is either infected machine or attacker (no spoofing is possible).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 384 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .target_state = &s_2_2},
		 /** 382 RST reset */
		 /** 384 A real event */
		 { .event_type = 7, .guard = &g_2_7, .target_state = &s_2_2} 
	 },
	 .transitions_count = 2
 };
 /** 417
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_2(){
		 return fsm_init( &s_2_0, &s_2_1, &s_2_2 );//init, error, final
 }//end function

 //======================================RULE 3======================================
 #define EVENTS_COUNT_3 2

 #define PROTO_ATTS_COUNT_3 4

 static proto_attribute_t proto_atts_3[ PROTO_ATTS_COUNT_3 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "dest_port", .att_id = 2, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "flags", .att_id = 6, .data_type = 0}};

 /** 484
  * Structure to represent event data
  */
 typedef struct _msg_struct_3{
	  const char *ip_dst;
	  const char *ip_src;
	  const double *tcp_dest_port;
	  const double *tcp_flags;
	  uint64_t timestamp;//timestamp
	  uint64_t counter;//index of packet
 }_msg_t_3;
 /** 519
  * Create an instance of _msg_t_3
  */
 static inline _msg_t_3* _allocate_msg_t_3(){
	 _msg_t_3 *m = mmt_malloc( sizeof( _msg_t_3 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_dest_port = NULL;
	 m->tcp_flags = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 543
  * Public API
  */
 static void *convert_message_to_event_3( const message_t *msg){
	 if( msg == NULL ) return NULL;
	 _msg_t_3 *new_msg = _allocate_msg_t_3( sizeof( _msg_t_3 ));
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i].proto_id ){/** 553 For each protocol*/
		 case 178:// protocol ip
			 switch( msg->elements[i].att_id ){
			 case 13:// attribute dst
				 new_msg->ip_dst = (char *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 }//end switch of att_id 560
			 break;
		 case 354:// protocol tcp
			 switch( msg->elements[i].att_id ){
			 case 2:// attribute dest_port
				 new_msg->tcp_dest_port = (double *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 case 6:// attribute flags
				 new_msg->tcp_flags = (double *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 }//end switch of att_id 577
		 }//end switch
	 }//end for
	 return (void *)new_msg; //580
 }//end function
 /** 449
  * Public API
  */
 static const uint16_t* hash_message_3( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_3 ];
	 size_t i;	 _msg_t_3 *msg = (_msg_t_3 *) data;
	 for( i=0; i<EVENTS_COUNT_3; i++) hash_table[i] = 0;/** 455 Rest hash_table. This is call for every executions*/
	 if( msg == NULL ) return hash_table;
	 if( msg->tcp_dest_port != NULL && msg->tcp_flags != NULL )
		 hash_table[ 0 ] = 8;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_flags != NULL )
		 hash_table[ 1 ] = 9;
	 return hash_table;
 }
 /** 91
  * Rule 3, event 8
  * SYN request
  */
 static inline int g_3_8( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_3 *his_data, *ev_data = (_msg_t_3 *) event_data;
	 if( ev_data->tcp_dest_port == NULL ) return 0;/* 62 */
	 double tcp_dest_port = *( ev_data->tcp_dest_port );
	 if( ev_data->tcp_flags == NULL ) return 0;/* 62 */
	 double tcp_flags = *( ev_data->tcp_flags );

	 return ((tcp_flags == 2) && (tcp_dest_port == 445));
 }
 
 /** 91
  * Rule 3, event 9
  * SYN ACK reply
  */
 static inline int g_3_9( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_3 *his_data, *ev_data = (_msg_t_3 *) event_data;
	 his_data = (_msg_t_3 *)fsm_get_history( fsm, 8);
	 if( his_data == NULL ) return 0;
	 if( his_data->ip_dst == NULL ) return 0;/* 62 */
	 const char *ip_dst_8 =  his_data->ip_dst ;
	 if( ev_data->ip_src == NULL ) return 0;/* 62 */
	 const char *ip_src =  ev_data->ip_src ;
	 if( ev_data->tcp_flags == NULL ) return 0;/* 62 */
	 double tcp_flags = *( ev_data->tcp_flags );

	 return ((tcp_flags == 18) && 0 == strcmp(ip_src , ip_dst_8));
 }
 
 /** 340
  * States of FSM for rule 3
  */
 
 /** 341
  * Predefine list of states: init, error, final, ...
  */
 static fsm_state_t s_3_0, s_3_1, s_3_2, s_3_3;
 /** 354
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 360
  * initial state
  */
  s_3_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  = "TCP SYN requests on microsoft-ds port 445 with SYN ACK.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 382 SYN request */
		 /** 384 A real event */
		 { .event_type = 8, .guard = &g_3_8, .target_state = &s_3_3} 
	 },
	 .transitions_count = 1
 },
 /** 360
  * timeout/error state
  */
  s_3_1 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 360
  * final state
  */
  s_3_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 360
  * root node
  */
  s_3_3 = {
	 .delay        = {.time_min = 0, .time_max = 6000000, .counter_min = 0, .counter_max = 0},
	 .description  = "TCP SYN requests on microsoft-ds port 445 with SYN ACK.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 384 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .target_state = &s_3_2},
		 /** 382 SYN ACK reply */
		 /** 384 A real event */
		 { .event_type = 9, .guard = &g_3_9, .target_state = &s_3_2},
		 /** 384 A real event will fire this loop to create a new instance */
		 { .event_type = 8, .guard = &g_3_8, .target_state = &s_3_3} 
	 },
	 .transitions_count = 3
 };
 /** 417
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_3(){
		 return fsm_init( &s_3_0, &s_3_1, &s_3_2 );//init, error, final
 }//end function

 //======================================RULE 4======================================
 #define EVENTS_COUNT_4 2

 #define PROTO_ATTS_COUNT_4 3

 static proto_attribute_t proto_atts_4[ PROTO_ATTS_COUNT_4 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "flags", .att_id = 6, .data_type = 0}};

 /** 484
  * Structure to represent event data
  */
 typedef struct _msg_struct_4{
	  const char *ip_dst;
	  const char *ip_src;
	  const double *tcp_flags;
	  uint64_t timestamp;//timestamp
	  uint64_t counter;//index of packet
 }_msg_t_4;
 /** 519
  * Create an instance of _msg_t_4
  */
 static inline _msg_t_4* _allocate_msg_t_4(){
	 _msg_t_4 *m = mmt_malloc( sizeof( _msg_t_4 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_flags = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 543
  * Public API
  */
 static void *convert_message_to_event_4( const message_t *msg){
	 if( msg == NULL ) return NULL;
	 _msg_t_4 *new_msg = _allocate_msg_t_4( sizeof( _msg_t_4 ));
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i].proto_id ){/** 553 For each protocol*/
		 case 178:// protocol ip
			 switch( msg->elements[i].att_id ){
			 case 13:// attribute dst
				 new_msg->ip_dst = (char *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 }//end switch of att_id 560
			 break;
		 case 354:// protocol tcp
			 switch( msg->elements[i].att_id ){
			 case 6:// attribute flags
				 new_msg->tcp_flags = (double *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 }//end switch of att_id 577
		 }//end switch
	 }//end for
	 return (void *)new_msg; //580
 }//end function
 /** 449
  * Public API
  */
 static const uint16_t* hash_message_4( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_4 ];
	 size_t i;	 _msg_t_4 *msg = (_msg_t_4 *) data;
	 for( i=0; i<EVENTS_COUNT_4; i++) hash_table[i] = 0;/** 455 Rest hash_table. This is call for every executions*/
	 if( msg == NULL ) return hash_table;
	 if( msg->tcp_flags != NULL )
		 hash_table[ 0 ] = 12;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_flags != NULL )
		 hash_table[ 1 ] = 13;
	 return hash_table;
 }
 /** 91
  * Rule 4, event 12
  * SYN request
  */
 static inline int g_4_12( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_4 *his_data, *ev_data = (_msg_t_4 *) event_data;
	 if( ev_data->tcp_flags == NULL ) return 0;/* 62 */
	 double tcp_flags = *( ev_data->tcp_flags );

	 return (tcp_flags == 2);
 }
 
 /** 91
  * Rule 4, event 13
  * SYN request
  */
 static inline int g_4_13( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_4 *his_data, *ev_data = (_msg_t_4 *) event_data;
	 his_data = (_msg_t_4 *)fsm_get_history( fsm, 12);
	 if( his_data == NULL ) return 0;
	 if( his_data->ip_dst == NULL ) return 0;/* 62 */
	 const char *ip_dst_12 =  his_data->ip_dst ;
	 if( ev_data->ip_dst == NULL ) return 0;/* 62 */
	 const char *ip_dst =  ev_data->ip_dst ;
	 his_data = (_msg_t_4 *)fsm_get_history( fsm, 12);
	 if( his_data == NULL ) return 0;
	 if( his_data->ip_src == NULL ) return 0;/* 62 */
	 const char *ip_src_12 =  his_data->ip_src ;
	 if( ev_data->ip_src == NULL ) return 0;/* 62 */
	 const char *ip_src =  ev_data->ip_src ;
	 if( ev_data->tcp_flags == NULL ) return 0;/* 62 */
	 double tcp_flags = *( ev_data->tcp_flags );

	 return ((tcp_flags == 2) && (0 == strcmp(ip_dst , ip_dst_12) && 0 == strcmp(ip_src , ip_src_12)));
 }
 
 /** 340
  * States of FSM for rule 4
  */
 
 /** 341
  * Predefine list of states: init, error, final, ...
  */
 static fsm_state_t s_4_0, s_4_1, s_4_2, s_4_3;
 /** 354
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 360
  * initial state
  */
  s_4_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  = "Two successive TCP SYN requests but with different destnation addresses.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 382 SYN request */
		 /** 384 A real event */
		 { .event_type = 12, .guard = &g_4_12, .target_state = &s_4_3} 
	 },
	 .transitions_count = 1
 },
 /** 360
  * timeout/error state
  */
  s_4_1 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 360
  * final state
  */
  s_4_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 360
  * root node
  */
  s_4_3 = {
	 .delay        = {.time_min = 0, .time_max = 1000000, .counter_min = 0, .counter_max = 0},
	 .description  = "Two successive TCP SYN requests but with different destnation addresses.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 384 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .target_state = &s_4_2},
		 /** 382 SYN request */
		 /** 384 A real event */
		 { .event_type = 13, .guard = &g_4_13, .target_state = &s_4_2},
		 /** 384 A real event will fire this loop to create a new instance */
		 { .event_type = 12, .guard = &g_4_12, .target_state = &s_4_3} 
	 },
	 .transitions_count = 3
 };
 /** 417
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_4(){
		 return fsm_init( &s_4_0, &s_4_1, &s_4_2 );//init, error, final
 }//end function

 //======================================RULE 5======================================
 #define EVENTS_COUNT_5 2

 #define PROTO_ATTS_COUNT_5 3

 static proto_attribute_t proto_atts_5[ PROTO_ATTS_COUNT_5 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "flags", .att_id = 6, .data_type = 0}};

 /** 484
  * Structure to represent event data
  */
 typedef struct _msg_struct_5{
	  const char *ip_dst;
	  const char *ip_src;
	  const double *tcp_flags;
	  uint64_t timestamp;//timestamp
	  uint64_t counter;//index of packet
 }_msg_t_5;
 /** 519
  * Create an instance of _msg_t_5
  */
 static inline _msg_t_5* _allocate_msg_t_5(){
	 _msg_t_5 *m = mmt_malloc( sizeof( _msg_t_5 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_flags = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 543
  * Public API
  */
 static void *convert_message_to_event_5( const message_t *msg){
	 if( msg == NULL ) return NULL;
	 _msg_t_5 *new_msg = _allocate_msg_t_5( sizeof( _msg_t_5 ));
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i].proto_id ){/** 553 For each protocol*/
		 case 178:// protocol ip
			 switch( msg->elements[i].att_id ){
			 case 13:// attribute dst
				 new_msg->ip_dst = (char *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 }//end switch of att_id 560
			 break;
		 case 354:// protocol tcp
			 switch( msg->elements[i].att_id ){
			 case 6:// attribute flags
				 new_msg->tcp_flags = (double *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 }//end switch of att_id 577
		 }//end switch
	 }//end for
	 return (void *)new_msg; //580
 }//end function
 /** 449
  * Public API
  */
 static const uint16_t* hash_message_5( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_5 ];
	 size_t i;	 _msg_t_5 *msg = (_msg_t_5 *) data;
	 for( i=0; i<EVENTS_COUNT_5; i++) hash_table[i] = 0;/** 455 Rest hash_table. This is call for every executions*/
	 if( msg == NULL ) return hash_table;
	 if( msg->tcp_flags != NULL )
		 hash_table[ 0 ] = 10;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_flags != NULL )
		 hash_table[ 1 ] = 11;
	 return hash_table;
 }
 /** 91
  * Rule 5, event 10
  * SYN request
  */
 static inline int g_5_10( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_5 *his_data, *ev_data = (_msg_t_5 *) event_data;
	 if( ev_data->tcp_flags == NULL ) return 0;/* 62 */
	 double tcp_flags = *( ev_data->tcp_flags );

	 return (tcp_flags == 2);
 }
 
 /** 91
  * Rule 5, event 11
  * SYN ACK replyyyyyy
  */
 static inline int g_5_11( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_5 *his_data, *ev_data = (_msg_t_5 *) event_data;
	 his_data = (_msg_t_5 *)fsm_get_history( fsm, 10);
	 if( his_data == NULL ) return 0;
	 if( his_data->ip_dst == NULL ) return 0;/* 62 */
	 const char *ip_dst_10 =  his_data->ip_dst ;
	 if( ev_data->ip_src == NULL ) return 0;/* 62 */
	 const char *ip_src =  ev_data->ip_src ;
	 if( ev_data->tcp_flags == NULL ) return 0;/* 62 */
	 double tcp_flags = *( ev_data->tcp_flags );

	 return ((tcp_flags == 18) && 0 == strcmp(ip_src , ip_dst_10));
 }
 
 /** 340
  * States of FSM for rule 5
  */
 
 /** 341
  * Predefine list of states: init, error, final, ...
  */
 static fsm_state_t s_5_0, s_5_1, s_5_2, s_5_3;
 /** 354
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 360
  * initial state
  */
  s_5_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  = "TCP SYN requests with SYN ACK.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 382 SYN request */
		 /** 384 A real event */
		 { .event_type = 10, .guard = &g_5_10, .target_state = &s_5_3} 
	 },
	 .transitions_count = 1
 },
 /** 360
  * timeout/error state
  */
  s_5_1 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 360
  * final state
  */
  s_5_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 360
  * root node
  */
  s_5_3 = {
	 .delay        = {.time_min = 0, .time_max = 60000000, .counter_min = 0, .counter_max = 0},
	 .description  = "TCP SYN requests with SYN ACK.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 384 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .target_state = &s_5_2},
		 /** 382 SYN ACK replyyyyyy */
		 /** 384 A real event */
		 { .event_type = 11, .guard = &g_5_11, .target_state = &s_5_2},
		 /** 384 A real event will fire this loop to create a new instance */
		 { .event_type = 10, .guard = &g_5_10, .target_state = &s_5_3} 
	 },
	 .transitions_count = 3
 };
 /** 417
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_5(){
		 return fsm_init( &s_5_0, &s_5_1, &s_5_2 );//init, error, final
 }//end function

 //======================================RULE 6======================================
 #define EVENTS_COUNT_6 2

 #define PROTO_ATTS_COUNT_6 2

 static proto_attribute_t proto_atts_6[ PROTO_ATTS_COUNT_6 ] = {{.proto = "http", .proto_id = 153, .att = "method", .att_id = 1, .data_type = 1}, {.proto = "http", .proto_id = 153, .att = "user_agent", .att_id = 7, .data_type = 1}};

 /** 484
  * Structure to represent event data
  */
 typedef struct _msg_struct_6{
	  const char *http_method;
	  const char *http_user_agent;
	  uint64_t timestamp;//timestamp
	  uint64_t counter;//index of packet
 }_msg_t_6;
 /** 519
  * Create an instance of _msg_t_6
  */
 static inline _msg_t_6* _allocate_msg_t_6(){
	 _msg_t_6 *m = mmt_malloc( sizeof( _msg_t_6 ));
	 m->http_method = NULL;
	 m->http_user_agent = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 543
  * Public API
  */
 static void *convert_message_to_event_6( const message_t *msg){
	 if( msg == NULL ) return NULL;
	 _msg_t_6 *new_msg = _allocate_msg_t_6( sizeof( _msg_t_6 ));
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i].proto_id ){/** 553 For each protocol*/
		 case 153:// protocol http
			 switch( msg->elements[i].att_id ){
			 case 1:// attribute method
				 new_msg->http_method = (char *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 case 7:// attribute user_agent
				 new_msg->http_user_agent = (char *) mmt_mem_retain( msg->elements[i].data );
				 break;
			 }//end switch of att_id 577
		 }//end switch
	 }//end for
	 return (void *)new_msg; //580
 }//end function
 /** 449
  * Public API
  */
 static const uint16_t* hash_message_6( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_6 ];
	 size_t i;	 _msg_t_6 *msg = (_msg_t_6 *) data;
	 for( i=0; i<EVENTS_COUNT_6; i++) hash_table[i] = 0;/** 455 Rest hash_table. This is call for every executions*/
	 if( msg == NULL ) return hash_table;
	 if( msg->http_method != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->http_user_agent != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 91
  * Rule 6, event 1
  * Having GET request
  */
 static inline int g_6_1( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_6 *his_data, *ev_data = (_msg_t_6 *) event_data;
	 if( ev_data->http_method == NULL ) return 0;/* 62 */
	 const char *http_method =  ev_data->http_method ;

	 return 0 == strcmp(http_method , "GET");
 }
 
 /** 91
  * Rule 6, event 2
  * Must have User-Agent
  */
 static inline int g_6_2( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_6 *his_data, *ev_data = (_msg_t_6 *) event_data;
	 if( ev_data->http_user_agent == NULL ) return 0;/* 62 */
	 const char *http_user_agent =  ev_data->http_user_agent ;

	 return 0 == strcmp(http_user_agent , "phantom");
 }
 
 /** 340
  * States of FSM for rule 6
  */
 
 /** 341
  * Predefine list of states: init, error, final, ...
  */
 static fsm_state_t s_6_0, s_6_1, s_6_2, s_6_3;
 /** 354
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 360
  * initial state
  */
  s_6_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  = "Get request from ghost",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 382 Having GET request */
		 /** 384 A real event */
		 { .event_type = 1, .guard = &g_6_1, .target_state = &s_6_3} 
	 },
	 .transitions_count = 1
 },
 /** 360
  * timeout/error state
  */
  s_6_1 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 360
  * final state
  */
  s_6_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 360
  * root node
  */
  s_6_3 = {
	 .delay        = {.time_min = 0, .time_max = 60000000, .counter_min = 0, .counter_max = 0},
	 .description  = "Get request from ghost",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 384 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .target_state = &s_6_2},
		 /** 382 Must have User-Agent */
		 /** 384 A real event */
		 { .event_type = 2, .guard = &g_6_2, .target_state = &s_6_2},
		 /** 384 A real event will fire this loop to create a new instance */
		 { .event_type = 1, .guard = &g_6_1, .target_state = &s_6_3} 
	 },
	 .transitions_count = 3
 };
 /** 417
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_6(){
		 return fsm_init( &s_6_0, &s_6_1, &s_6_2 );//init, error, final
 }//end function

 //======================================GENERAL======================================
 /** 593
  * Information of 6 rules
  */
 size_t mmt_sec_get_plugin_info( const rule_info_t **rules_arr ){
	  static const rule_info_t rules[] = (rule_info_t[]){
		 {
			 .id               = 1,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_1,
			 .proto_atts_count = PROTO_ATTS_COUNT_1,
			 .proto_atts       = proto_atts_1,
			 .description      = "Several attempts to connect via ssh (brute force attack). Source address is either infected machine or attacker (no spoofing is possible).",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_1,
			 .hash_message     = &hash_message_1,
			 .convert_message  = &convert_message_to_event_1
		 },
		 {
			 .id               = 2,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_2,
			 .proto_atts_count = PROTO_ATTS_COUNT_2,
			 .proto_atts       = proto_atts_2,
			 .description      = "Attempted to connect via ssh but reseted immediately. Source address is either infected machine or attacker (no spoofing is possible).",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_2,
			 .hash_message     = &hash_message_2,
			 .convert_message  = &convert_message_to_event_2
		 },
		 {
			 .id               = 3,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_3,
			 .proto_atts_count = PROTO_ATTS_COUNT_3,
			 .proto_atts       = proto_atts_3,
			 .description      = "TCP SYN requests on microsoft-ds port 445 with SYN ACK.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_3,
			 .hash_message     = &hash_message_3,
			 .convert_message  = &convert_message_to_event_3
		 },
		 {
			 .id               = 4,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_4,
			 .proto_atts_count = PROTO_ATTS_COUNT_4,
			 .proto_atts       = proto_atts_4,
			 .description      = "Two successive TCP SYN requests but with different destnation addresses.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_4,
			 .hash_message     = &hash_message_4,
			 .convert_message  = &convert_message_to_event_4
		 },
		 {
			 .id               = 5,
			 .type_id          = 1,
			 .type_string      = "security",
			 .events_count     = EVENTS_COUNT_5,
			 .proto_atts_count = PROTO_ATTS_COUNT_5,
			 .proto_atts       = proto_atts_5,
			 .description      = "TCP SYN requests with SYN ACK.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = "py_createstix(4_TCP_SYN_request_without_SYN_ACK_could_be_a_spoofed_address, ip.src.10)",
			 .create_instance  = &create_new_fsm_5,
			 .hash_message     = &hash_message_5,
			 .convert_message  = &convert_message_to_event_5
		 },
		 {
			 .id               = 6,
			 .type_id          = 1,
			 .type_string      = "security",
			 .events_count     = EVENTS_COUNT_6,
			 .proto_atts_count = PROTO_ATTS_COUNT_6,
			 .proto_atts       = proto_atts_6,
			 .description      = "Get request from ghost",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_6,
			 .hash_message     = &hash_message_6,
			 .convert_message  = &convert_message_to_event_6
		 }
	 };
	 *rules_arr = rules;
	 return 6;
 }