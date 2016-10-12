
 /** 667
  * This file is generated automatically on 2016-10-12 17:48:03
  */
 #include <string.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include "plugin_header.h"
 #include "mmt_fsm.h"
 #include "mmt_alloc.h"
 

 //======================================RULE 1======================================
 /** 475
  * Structure to represent event data
  */
 typedef struct _msg_struct_1{
	  const char *ip_dst;
	  const char *ip_src;
	  double tcp_dest_port;
	  double tcp_flags;
	  double tcp_src_port;
	  uint64_t timestamp;//timestamp
	  uint64_t counter;//index of packet
 }_msg_t_1;
 /** 497
  * Create an instance of _msg_t_1
  */
 static inline _msg_t_1* _allocate_msg_t_1(){
	 _msg_t_1 *m = mmt_malloc( sizeof( _msg_t_1 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_dest_port = 0 ;
	 m->tcp_flags = 0 ;
	 m->tcp_src_port = 0 ;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 523
  * Public API
  */
 void *mmt_sec_convert_message_to_event_1( const message_t *msg){
	 if( msg == NULL ) return NULL;
	 _msg_t_1 *new_msg = _allocate_msg_t_1( sizeof( _msg_t_1 ));
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
mmt_debug( "VERIFY %zu elements", msg->elements_count );
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i]->proto_id ){/** 533 For each protocol*/
		 case 178:// protocol ip
			 switch( msg->elements[i]->att_id ){
			 case 13:// attribute dst
				 new_msg->ip_dst = mmt_mem_retain( msg->elements[i]->data );
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = mmt_mem_retain( msg->elements[i]->data );
				 break;
			 }//end switch of att_id 540
			 break;
		 case 354:// protocol tcp
			 switch( msg->elements[i]->att_id ){
			 case 2:// attribute dest_port
				 new_msg->tcp_dest_port = *(double *)msg->elements[i]->data;
mmt_debug("=====tcp_dest_port: %.2f", new_msg->tcp_flags );
				 break;
			 case 6:// attribute flags
				 new_msg->tcp_flags = *(double *)msg->elements[i]->data;
mmt_debug("=====tcp_flags: %.2f", new_msg->tcp_flags );
				 break;
			 case 1:// attribute src_port
				 new_msg->tcp_src_port = *(double *)msg->elements[i]->data;
				 break;
			 }//end switch of att_id 559
		 }//end switch
	 }//end for
	 return (void *)new_msg; //562
 }//end function
 /** 435
  * Public API
  */
 void* mmt_sec_hash_message_1( const message_t *msg, uint32_t *tran_index){
	 _msg_t_1 *ev = mmt_malloc( sizeof( _msg_t_1 ));
	 size_t i;	 message_element_t *e;
	 for( i=0; i<msg->elements_count; i++){
		 e = msg->elements[i];
	 switch( e->proto_id ){
 /** 449
  * ip
  */
 	 case 178:
		 switch ( e->att_id){
		 case 13:	 //dst
			 return NULL;//0;
		 case 12:	 //src
			 return NULL;//1;
		 }//end att for 178
 /** 449
  * tcp
  */
 	 case 354:
		 switch ( e->att_id){
		 case 2:	 //dest_port
			 return NULL;//2;
		 case 6:	 //flags
			 return NULL;//3;
		 case 1:	 //src_port
			 return NULL;//4;
		 }//last switch
	 }}
 return NULL; }
 /** 86
  * Rule 1, event 1
  * SYN request
  */
 static inline int g_1_1( void *condition, const fsm_event_t *event, const fsm_t *fsm ){
	 if( event->data == NULL ) return 0;
	 const _msg_t_1 *ev_data, *his_data;
	 ev_data = (_msg_t_1 *)event->data;/* 58 */
	 double tcp_dest_port = ev_data->tcp_dest_port;/* 58 */
	 double tcp_flags = ev_data->tcp_flags;

printf("GUARD======== %.2f, %.2f", tcp_flags, tcp_dest_port );

	 return ((tcp_flags == 2) && (tcp_dest_port == 22));
 }
 
 /** 86
  * Rule 1, event 2
  * SYN ACK reply
  */
 static inline int g_1_2( void *condition, const fsm_event_t *event, const fsm_t *fsm ){
	 if( event->data == NULL ) return 0;
	 const _msg_t_1 *ev_data, *his_data;
	 ev_data = (_msg_t_1 *)event->data;
	 his_data = (_msg_t_1 *)fsm_get_history( fsm, 1);
	 if( his_data == NULL ) return 0;/* 58 */
	 const char *ip_dst_1 = his_data->ip_dst;
	 if( ip_dst_1 == NULL ) return 0;/* 58 */
	 const char *ip_dst = ev_data->ip_dst;
	 if( ip_dst == NULL ) return 0;
	 his_data = (_msg_t_1 *)fsm_get_history( fsm, 1);
	 if( his_data == NULL ) return 0;/* 58 */
	 const char *ip_src_1 = his_data->ip_src;
	 if( ip_src_1 == NULL ) return 0;/* 58 */
	 const char *ip_src = ev_data->ip_src;
	 if( ip_src == NULL ) return 0;/* 58 */
	 double tcp_flags = ev_data->tcp_flags;/* 58 */
	 double tcp_src_port = ev_data->tcp_src_port;

	 return ((tcp_flags == 18) && ((tcp_src_port == 22) && (0 == strcmp(ip_dst , ip_src_1) && 0 == strcmp(ip_src , ip_dst_1))));
 }
 
 /** 86
  * Rule 1, event 3
  * SYN request
  */
 static inline int g_1_3( void *condition, const fsm_event_t *event, const fsm_t *fsm ){
	 if( event->data == NULL ) return 0;
	 const _msg_t_1 *ev_data, *his_data;
	 ev_data = (_msg_t_1 *)event->data;
	 his_data = (_msg_t_1 *)fsm_get_history( fsm, 1);
	 if( his_data == NULL ) return 0;/* 58 */
	 const char *ip_dst_1 = his_data->ip_dst;
	 if( ip_dst_1 == NULL ) return 0;/* 58 */
	 const char *ip_dst = ev_data->ip_dst;
	 if( ip_dst == NULL ) return 0;
	 his_data = (_msg_t_1 *)fsm_get_history( fsm, 1);
	 if( his_data == NULL ) return 0;/* 58 */
	 const char *ip_src_1 = his_data->ip_src;
	 if( ip_src_1 == NULL ) return 0;/* 58 */
	 const char *ip_src = ev_data->ip_src;
	 if( ip_src == NULL ) return 0;/* 58 */
	 double tcp_dest_port = ev_data->tcp_dest_port;/* 58 */
	 double tcp_flags = ev_data->tcp_flags;

	 return ((tcp_flags == 2) && ((tcp_dest_port == 22) && (0 == strcmp(ip_src , ip_src_1) && 0 == strcmp(ip_dst , ip_dst_1))));
 }
 
 /** 86
  * Rule 1, event 4
  * SYN ACK reply
  */
 static inline int g_1_4( void *condition, const fsm_event_t *event, const fsm_t *fsm ){
	 if( event->data == NULL ) return 0;
	 const _msg_t_1 *ev_data, *his_data;
	 ev_data = (_msg_t_1 *)event->data;
	 his_data = (_msg_t_1 *)fsm_get_history( fsm, 1);
	 if( his_data == NULL ) return 0;/* 58 */
	 const char *ip_dst_1 = his_data->ip_dst;
	 if( ip_dst_1 == NULL ) return 0;/* 58 */
	 const char *ip_dst = ev_data->ip_dst;
	 if( ip_dst == NULL ) return 0;
	 his_data = (_msg_t_1 *)fsm_get_history( fsm, 1);
	 if( his_data == NULL ) return 0;/* 58 */
	 const char *ip_src_1 = his_data->ip_src;
	 if( ip_src_1 == NULL ) return 0;/* 58 */
	 const char *ip_src = ev_data->ip_src;
	 if( ip_src == NULL ) return 0;/* 58 */
	 double tcp_flags = ev_data->tcp_flags;/* 58 */
	 double tcp_src_port = ev_data->tcp_src_port;

	 return ((tcp_flags == 18) && ((tcp_src_port == 22) && (0 == strcmp(ip_dst , ip_src_1) && 0 == strcmp(ip_src , ip_dst_1))));
 }
 
 /** 337
  * States of FSM for rule 1
  */
 
 /** 338
  * Predefine list of states: init, error, final, ...
  */
 static fsm_state_t s_1_0, s_1_1, s_1_2, s_1_3, s_1_4, s_1_5;
 /** 351
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 357
  * initial state
  */
  s_1_0 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 0.00, .counter_min = 0, .counter_max = 0},
	 .description  = "Several attempts to connect via ssh (brute force attack). Source address is either infected machine or attacker (no spoofing is possible).",
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = (fsm_transition_t[]){
		 /** 381 SYN request */
		 { .event_type = 0, .condition = NULL, .guard = &g_1_1, .action = NULL, .target_state = &s_1_3} 
	 },
	 .transitions_count = 1
 },
 /** 357
  * timeout/error state
  */
  s_1_1 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 0.00, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 357
  * final state
  */
  s_1_2 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 0.00, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_1_3 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 1.00, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0,
	 .exit_action  = 1,
	 .transitions  = (fsm_transition_t[]){
		 { .event_type = 1, .condition = NULL, .guard = NULL  , .action = NULL, .target_state = &s_1_4},
		 /** 381 SYN ACK reply */
		 { .event_type = 0, .condition = NULL, .guard = &g_1_2, .action = NULL, .target_state = &s_1_4},
		 /** 383 Loop to create a new instance */
		 { .event_type = 0, .condition = NULL, .guard = &g_1_1, .action = NULL, .target_state = &s_1_3} 
	 },
	 .transitions_count = 3
 },
 /** 357
  * root node
  */
  s_1_4 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 1.00, .counter_min = 0, .counter_max = 0},
	 .description  = "Several attempts to connect via ssh (brute force attack). Source address is either infected machine or attacker (no spoofing is possible).",
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = (fsm_transition_t[]){
		 { .event_type = 1, .condition = NULL, .guard = NULL  , .action = NULL, .target_state = &s_1_2},
		 /** 381 SYN request */
		 { .event_type = 0, .condition = NULL, .guard = &g_1_3, .action = NULL, .target_state = &s_1_5} 
	 },
	 .transitions_count = 2
 }, s_1_5 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 1.00, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0,
	 .exit_action  = 1,
	 .transitions  = (fsm_transition_t[]){
		 { .event_type = 1, .condition = NULL, .guard = NULL  , .action = NULL, .target_state = &s_1_1},
		 /** 381 SYN ACK reply */
		 { .event_type = 0, .condition = NULL, .guard = &g_1_4, .action = NULL, .target_state = &s_1_2},
		 /** 383 Loop to create a new instance */
		 { .event_type = 0, .condition = NULL, .guard = &g_1_3, .action = NULL, .target_state = &s_1_5} 
	 },
	 .transitions_count = 3
 };
 /** 404
  * Array to quickly access to a state by index
  */
 static fsm_state_t* s_1[6] = {&s_1_0, &s_1_1, &s_1_2, &s_1_3, &s_1_4, &s_1_5};
 /** 414
  * Create a new FSM for this rule
  */
 void *mmt_sec_create_new_fsm_1(){
		 return fsm_init( &s_1_0, &s_1_1, &s_1_2 );//init, error, final
 }//end function

 //======================================RULE 2======================================
 /** 475
  * Structure to represent event data
  */
 typedef struct _msg_struct_2{
	  const char *ip_dst;
	  const char *ip_src;
	  double tcp_dest_port;
	  double tcp_flags;
	  double tcp_src_port;
	  uint64_t timestamp;//timestamp
	  uint64_t counter;//index of packet
 }_msg_t_2;
 /** 497
  * Create an instance of _msg_t_2
  */
 static inline _msg_t_2* _allocate_msg_t_2(){
	 _msg_t_2 *m = mmt_malloc( sizeof( _msg_t_2 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_dest_port = 0 ;
	 m->tcp_flags = 0 ;
	 m->tcp_src_port = 0 ;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 523
  * Public API
  */
 void *mmt_sec_convert_message_to_event_2( const message_t *msg){
	 if( msg == NULL ) return NULL;
	 _msg_t_2 *new_msg = _allocate_msg_t_2( sizeof( _msg_t_2 ));
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i]->proto_id ){/** 533 For each protocol*/
		 case 178:// protocol ip
			 switch( msg->elements[i]->att_id ){
			 case 13:// attribute dst
				 new_msg->ip_dst = mmt_mem_retain( msg->elements[i]->data );
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = mmt_mem_retain( msg->elements[i]->data );
				 break;
			 }//end switch of att_id 540
			 break;
		 case 354:// protocol tcp
			 switch( msg->elements[i]->att_id ){
			 case 2:// attribute dest_port
				 new_msg->tcp_dest_port = *(double *)msg->elements[i]->data;
				 break;
			 case 6:// attribute flags
				 new_msg->tcp_flags = *(double *)msg->elements[i]->data;
				 break;
			 case 1:// attribute src_port
				 new_msg->tcp_src_port = *(double *)msg->elements[i]->data;
				 break;
			 }//end switch of att_id 559
		 }//end switch
	 }//end for
	 return (void *)new_msg; //562
 }//end function
 /** 435
  * Public API
  */
 void* mmt_sec_hash_message_2( const message_t *msg, uint32_t *tran_index){
	 _msg_t_2 *ev = mmt_malloc( sizeof( _msg_t_2 ));
	 size_t i;	 message_element_t *e;
	 for( i=0; i<msg->elements_count; i++){
		 e = msg->elements[i];
	 switch( e->proto_id ){
 /** 449
  * ip
  */
 	 case 178:
		 switch ( e->att_id){
		 case 13:	 //dst
			 return NULL;//0;
		 case 12:	 //src
			 return NULL;//1;
		 }//end att for 178
 /** 449
  * tcp
  */
 	 case 354:
		 switch ( e->att_id){
		 case 2:	 //dest_port
			 return NULL;//2;
		 case 6:	 //flags
			 return NULL;//3;
		 case 1:	 //src_port
			 return NULL;//4;
		 }//last switch
	 }}
 return NULL; }
 /** 86
  * Rule 2, event 5
  * SYN request
  */
 static inline int g_2_5( void *condition, const fsm_event_t *event, const fsm_t *fsm ){
	 if( event->data == NULL ) return 0;
	 const _msg_t_2 *ev_data, *his_data;
	 ev_data = (_msg_t_2 *)event->data;/* 58 */
	 double tcp_dest_port = ev_data->tcp_dest_port;/* 58 */
	 double tcp_flags = ev_data->tcp_flags;

	 return ((tcp_flags == 2) && (tcp_dest_port == 22));
 }
 
 /** 86
  * Rule 2, event 6
  * SYN ACK reply
  */
 static inline int g_2_6( void *condition, const fsm_event_t *event, const fsm_t *fsm ){
	 if( event->data == NULL ) return 0;
	 const _msg_t_2 *ev_data, *his_data;
	 ev_data = (_msg_t_2 *)event->data;
	 his_data = (_msg_t_2 *)fsm_get_history( fsm, 5);
	 if( his_data == NULL ) return 0;/* 58 */
	 const char *ip_dst_5 = his_data->ip_dst;
	 if( ip_dst_5 == NULL ) return 0;/* 58 */
	 const char *ip_dst = ev_data->ip_dst;
	 if( ip_dst == NULL ) return 0;
	 his_data = (_msg_t_2 *)fsm_get_history( fsm, 5);
	 if( his_data == NULL ) return 0;/* 58 */
	 const char *ip_src_5 = his_data->ip_src;
	 if( ip_src_5 == NULL ) return 0;/* 58 */
	 const char *ip_src = ev_data->ip_src;
	 if( ip_src == NULL ) return 0;/* 58 */
	 double tcp_flags = ev_data->tcp_flags;/* 58 */
	 double tcp_src_port = ev_data->tcp_src_port;

	 return ((tcp_flags == 18) && ((tcp_src_port == 22) && (0 == strcmp(ip_dst , ip_src_5) && 0 == strcmp(ip_src , ip_dst_5))));
 }
 
 /** 86
  * Rule 2, event 7
  * RST reset
  */
 static inline int g_2_7( void *condition, const fsm_event_t *event, const fsm_t *fsm ){
	 if( event->data == NULL ) return 0;
	 const _msg_t_2 *ev_data, *his_data;
	 ev_data = (_msg_t_2 *)event->data;
	 his_data = (_msg_t_2 *)fsm_get_history( fsm, 5);
	 if( his_data == NULL ) return 0;/* 58 */
	 const char *ip_dst_5 = his_data->ip_dst;
	 if( ip_dst_5 == NULL ) return 0;/* 58 */
	 const char *ip_dst = ev_data->ip_dst;
	 if( ip_dst == NULL ) return 0;
	 his_data = (_msg_t_2 *)fsm_get_history( fsm, 5);
	 if( his_data == NULL ) return 0;/* 58 */
	 const char *ip_src_5 = his_data->ip_src;
	 if( ip_src_5 == NULL ) return 0;/* 58 */
	 const char *ip_src = ev_data->ip_src;
	 if( ip_src == NULL ) return 0;/* 58 */
	 double tcp_dest_port = ev_data->tcp_dest_port;/* 58 */
	 double tcp_flags = ev_data->tcp_flags;

	 return ((tcp_flags == 4) && ((tcp_dest_port == 22) && (0 == strcmp(ip_dst , ip_dst_5) && 0 == strcmp(ip_src , ip_src_5))));
 }
 
 /** 337
  * States of FSM for rule 2
  */
 
 /** 338
  * Predefine list of states: init, error, final, ...
  */
 static fsm_state_t s_2_0, s_2_1, s_2_2, s_2_3, s_2_4, s_2_5;
 /** 351
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 357
  * initial state
  */
  s_2_0 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 0.00, .counter_min = 0, .counter_max = 0},
	 .description  = "Attempted to connect via ssh but reseted immediately. Source address is either infected machine or attacker (no spoofing is possible).",
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = (fsm_transition_t[]){
		 /** 381 SYN request */
		 { .event_type = 0, .condition = NULL, .guard = &g_2_5, .action = NULL, .target_state = &s_2_3},
		 /** 381 SYN ACK reply */
		 { .event_type = 0, .condition = NULL, .guard = &g_2_6, .action = NULL, .target_state = &s_2_4} 
	 },
	 .transitions_count = 2
 },
 /** 357
  * timeout/error state
  */
  s_2_1 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 0.00, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 357
  * final state
  */
  s_2_2 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 0.00, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_2_3 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 1.00, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0,
	 .exit_action  = 1,
	 .transitions  = (fsm_transition_t[]){
		 { .event_type = 1, .condition = NULL, .guard = NULL  , .action = NULL, .target_state = &s_2_5},
		 /** 381 SYN ACK reply */
		 { .event_type = 0, .condition = NULL, .guard = &g_2_6, .action = NULL, .target_state = &s_2_5},
		 /** 383 Loop to create a new instance */
		 { .event_type = 0, .condition = NULL, .guard = &g_2_5, .action = NULL, .target_state = &s_2_3} 
	 },
	 .transitions_count = 3
 }, s_2_4 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 1.00, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0,
	 .exit_action  = 1,
	 .transitions  = (fsm_transition_t[]){
		 { .event_type = 1, .condition = NULL, .guard = NULL  , .action = NULL, .target_state = &s_2_5},
		 /** 381 SYN request */
		 { .event_type = 0, .condition = NULL, .guard = &g_2_5, .action = NULL, .target_state = &s_2_5},
		 /** 383 Loop to create a new instance */
		 { .event_type = 0, .condition = NULL, .guard = &g_2_6, .action = NULL, .target_state = &s_2_4} 
	 },
	 .transitions_count = 3
 },
 /** 357
  * root node
  */
  s_2_5 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 244.00, .counter_min = 0, .counter_max = 0},
	 .description  = "Attempted to connect via ssh but reseted immediately. Source address is either infected machine or attacker (no spoofing is possible).",
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = (fsm_transition_t[]){
		 { .event_type = 1, .condition = NULL, .guard = NULL  , .action = NULL, .target_state = &s_2_2},
		 /** 381 RST reset */
		 { .event_type = 0, .condition = NULL, .guard = &g_2_7, .action = NULL, .target_state = &s_2_2} 
	 },
	 .transitions_count = 2
 };
 /** 404
  * Array to quickly access to a state by index
  */
 static fsm_state_t* s_2[6] = {&s_2_0, &s_2_1, &s_2_2, &s_2_3, &s_2_4, &s_2_5};
 /** 414
  * Create a new FSM for this rule
  */
 void *mmt_sec_create_new_fsm_2(){
		 return fsm_init( &s_2_0, &s_2_1, &s_2_2 );//init, error, final
 }//end function

 //======================================RULE 3======================================
 /** 475
  * Structure to represent event data
  */
 typedef struct _msg_struct_3{
	  const char *ip_dst;
	  const char *ip_src;
	  double tcp_dest_port;
	  double tcp_flags;
	  uint64_t timestamp;//timestamp
	  uint64_t counter;//index of packet
 }_msg_t_3;
 /** 497
  * Create an instance of _msg_t_3
  */
 static inline _msg_t_3* _allocate_msg_t_3(){
	 _msg_t_3 *m = mmt_malloc( sizeof( _msg_t_3 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_dest_port = 0 ;
	 m->tcp_flags = 0 ;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 523
  * Public API
  */
 void *mmt_sec_convert_message_to_event_3( const message_t *msg){
	 if( msg == NULL ) return NULL;
	 _msg_t_3 *new_msg = _allocate_msg_t_3( sizeof( _msg_t_3 ));
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i]->proto_id ){/** 533 For each protocol*/
		 case 178:// protocol ip
			 switch( msg->elements[i]->att_id ){
			 case 13:// attribute dst
				 new_msg->ip_dst = mmt_mem_retain( msg->elements[i]->data );
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = mmt_mem_retain( msg->elements[i]->data );
				 break;
			 }//end switch of att_id 540
			 break;
		 case 354:// protocol tcp
			 switch( msg->elements[i]->att_id ){
			 case 2:// attribute dest_port
				 new_msg->tcp_dest_port = *(double *)msg->elements[i]->data;
				 break;
			 case 6:// attribute flags
				 new_msg->tcp_flags = *(double *)msg->elements[i]->data;
				 break;
			 }//end switch of att_id 559
		 }//end switch
	 }//end for
	 return (void *)new_msg; //562
 }//end function
 /** 435
  * Public API
  */
 void* mmt_sec_hash_message_3( const message_t *msg, uint32_t *tran_index){
	 _msg_t_3 *ev = mmt_malloc( sizeof( _msg_t_3 ));
	 size_t i;	 message_element_t *e;
	 for( i=0; i<msg->elements_count; i++){
		 e = msg->elements[i];
	 switch( e->proto_id ){
 /** 449
  * ip
  */
 	 case 178:
		 switch ( e->att_id){
		 case 13:	 //dst
			 return NULL;//0;
		 case 12:	 //src
			 return NULL;//1;
		 }//end att for 178
 /** 449
  * tcp
  */
 	 case 354:
		 switch ( e->att_id){
		 case 2:	 //dest_port
			 return NULL;//2;
		 case 6:	 //flags
			 return NULL;//3;
		 }//last switch
	 }}
 return NULL; }
 /** 86
  * Rule 3, event 8
  * SYN request
  */
 static inline int g_3_8( void *condition, const fsm_event_t *event, const fsm_t *fsm ){
	 if( event->data == NULL ) return 0;
	 const _msg_t_3 *ev_data, *his_data;
	 ev_data = (_msg_t_3 *)event->data;/* 58 */
	 double tcp_dest_port = ev_data->tcp_dest_port;/* 58 */
	 double tcp_flags = ev_data->tcp_flags;

	 return ((tcp_flags == 2) && (tcp_dest_port == 445));
 }
 
 /** 86
  * Rule 3, event 9
  * SYN ACK reply
  */
 static inline int g_3_9( void *condition, const fsm_event_t *event, const fsm_t *fsm ){
	 if( event->data == NULL ) return 0;
	 const _msg_t_3 *ev_data, *his_data;
	 ev_data = (_msg_t_3 *)event->data;
	 his_data = (_msg_t_3 *)fsm_get_history( fsm, 8);
	 if( his_data == NULL ) return 0;/* 58 */
	 const char *ip_dst_8 = his_data->ip_dst;
	 if( ip_dst_8 == NULL ) return 0;/* 58 */
	 const char *ip_src = ev_data->ip_src;
	 if( ip_src == NULL ) return 0;/* 58 */
	 double tcp_flags = ev_data->tcp_flags;

	 return ((tcp_flags == 18) && 0 == strcmp(ip_src , ip_dst_8));
 }
 
 /** 337
  * States of FSM for rule 3
  */
 
 /** 338
  * Predefine list of states: init, error, final, ...
  */
 static fsm_state_t s_3_0, s_3_1, s_3_2, s_3_3;
 /** 351
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 357
  * initial state
  */
  s_3_0 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 0.00, .counter_min = 0, .counter_max = 0},
	 .description  = "TCP SYN requests on microsoft-ds port 445 with SYN ACK.",
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = (fsm_transition_t[]){
		 /** 381 SYN request */
		 { .event_type = 0, .condition = NULL, .guard = &g_3_8, .action = NULL, .target_state = &s_3_3} 
	 },
	 .transitions_count = 1
 },
 /** 357
  * timeout/error state
  */
  s_3_1 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 0.00, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 357
  * final state
  */
  s_3_2 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 0.00, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 357
  * root node
  */
  s_3_3 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 6.00, .counter_min = 0, .counter_max = 0},
	 .description  = "TCP SYN requests on microsoft-ds port 445 with SYN ACK.",
	 .entry_action = 0,
	 .exit_action  = 1,
	 .transitions  = (fsm_transition_t[]){
		 { .event_type = 1, .condition = NULL, .guard = NULL  , .action = NULL, .target_state = &s_3_2},
		 /** 381 SYN ACK reply */
		 { .event_type = 0, .condition = NULL, .guard = &g_3_9, .action = NULL, .target_state = &s_3_2},
		 /** 383 Loop to create a new instance */
		 { .event_type = 0, .condition = NULL, .guard = &g_3_8, .action = NULL, .target_state = &s_3_3} 
	 },
	 .transitions_count = 3
 };
 /** 404
  * Array to quickly access to a state by index
  */
 static fsm_state_t* s_3[4] = {&s_3_0, &s_3_1, &s_3_2, &s_3_3};
 /** 414
  * Create a new FSM for this rule
  */
 void *mmt_sec_create_new_fsm_3(){
		 return fsm_init( &s_3_0, &s_3_1, &s_3_2 );//init, error, final
 }//end function

 //======================================RULE 4======================================
 /** 475
  * Structure to represent event data
  */
 typedef struct _msg_struct_4{
	  const char *ip_dst;
	  const char *ip_src;
	  double tcp_flags;
	  uint64_t timestamp;//timestamp
	  uint64_t counter;//index of packet
 }_msg_t_4;
 /** 497
  * Create an instance of _msg_t_4
  */
 static inline _msg_t_4* _allocate_msg_t_4(){
	 _msg_t_4 *m = mmt_malloc( sizeof( _msg_t_4 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_flags = 0 ;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 523
  * Public API
  */
 void *mmt_sec_convert_message_to_event_4( const message_t *msg){
	 if( msg == NULL ) return NULL;
	 _msg_t_4 *new_msg = _allocate_msg_t_4( sizeof( _msg_t_4 ));
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i]->proto_id ){/** 533 For each protocol*/
		 case 178:// protocol ip
			 switch( msg->elements[i]->att_id ){
			 case 13:// attribute dst
				 new_msg->ip_dst = mmt_mem_retain( msg->elements[i]->data );
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = mmt_mem_retain( msg->elements[i]->data );
				 break;
			 }//end switch of att_id 540
			 break;
		 case 354:// protocol tcp
			 switch( msg->elements[i]->att_id ){
			 case 6:// attribute flags
				 new_msg->tcp_flags = *(double *)msg->elements[i]->data;
				 break;
			 }//end switch of att_id 559
		 }//end switch
	 }//end for
	 return (void *)new_msg; //562
 }//end function
 /** 435
  * Public API
  */
 void* mmt_sec_hash_message_4( const message_t *msg, uint32_t *tran_index){
	 _msg_t_4 *ev = mmt_malloc( sizeof( _msg_t_4 ));
	 size_t i;	 message_element_t *e;
	 for( i=0; i<msg->elements_count; i++){
		 e = msg->elements[i];
	 switch( e->proto_id ){
 /** 449
  * ip
  */
 	 case 178:
		 switch ( e->att_id){
		 case 13:	 //dst
			 return NULL;//0;
		 case 12:	 //src
			 return NULL;//1;
		 }//end att for 178
 /** 449
  * tcp
  */
 	 case 354:
		 switch ( e->att_id){
		 case 6:	 //flags
			 return NULL;//2;
		 }//last switch
	 }}
 return NULL; }
 /** 86
  * Rule 4, event 12
  * SYN request
  */
 static inline int g_4_12( void *condition, const fsm_event_t *event, const fsm_t *fsm ){
	 if( event->data == NULL ) return 0;
	 const _msg_t_4 *ev_data, *his_data;
	 ev_data = (_msg_t_4 *)event->data;/* 58 */
	 double tcp_flags = ev_data->tcp_flags;

	 return (tcp_flags == 2);
 }
 
 /** 86
  * Rule 4, event 13
  * SYN request
  */
 static inline int g_4_13( void *condition, const fsm_event_t *event, const fsm_t *fsm ){
	 if( event->data == NULL ) return 0;
	 const _msg_t_4 *ev_data, *his_data;
	 ev_data = (_msg_t_4 *)event->data;
	 his_data = (_msg_t_4 *)fsm_get_history( fsm, 12);
	 if( his_data == NULL ) return 0;/* 58 */
	 const char *ip_dst_12 = his_data->ip_dst;
	 if( ip_dst_12 == NULL ) return 0;/* 58 */
	 const char *ip_dst = ev_data->ip_dst;
	 if( ip_dst == NULL ) return 0;
	 his_data = (_msg_t_4 *)fsm_get_history( fsm, 12);
	 if( his_data == NULL ) return 0;/* 58 */
	 const char *ip_src_12 = his_data->ip_src;
	 if( ip_src_12 == NULL ) return 0;/* 58 */
	 const char *ip_src = ev_data->ip_src;
	 if( ip_src == NULL ) return 0;/* 58 */
	 double tcp_flags = ev_data->tcp_flags;

	 return ((tcp_flags == 2) && (0 != strcmp(ip_dst , ip_dst_12) && 0 == strcmp(ip_src , ip_src_12)));
 }
 
 /** 337
  * States of FSM for rule 4
  */
 
 /** 338
  * Predefine list of states: init, error, final, ...
  */
 static fsm_state_t s_4_0, s_4_1, s_4_2, s_4_3;
 /** 351
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 357
  * initial state
  */
  s_4_0 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 0.00, .counter_min = 0, .counter_max = 0},
	 .description  = "Two successive TCP SYN requests but with different destnation addresses.",
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = (fsm_transition_t[]){
		 /** 381 SYN request */
		 { .event_type = 0, .condition = NULL, .guard = &g_4_12, .action = NULL, .target_state = &s_4_3} 
	 },
	 .transitions_count = 1
 },
 /** 357
  * timeout/error state
  */
  s_4_1 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 0.00, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 357
  * final state
  */
  s_4_2 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 0.00, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 357
  * root node
  */
  s_4_3 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 1.00, .counter_min = 0, .counter_max = 0},
	 .description  = "Two successive TCP SYN requests but with different destnation addresses.",
	 .entry_action = 0,
	 .exit_action  = 1,
	 .transitions  = (fsm_transition_t[]){
		 { .event_type = 1, .condition = NULL, .guard = NULL  , .action = NULL, .target_state = &s_4_2},
		 /** 381 SYN request */
		 { .event_type = 0, .condition = NULL, .guard = &g_4_13, .action = NULL, .target_state = &s_4_2},
		 /** 383 Loop to create a new instance */
		 { .event_type = 0, .condition = NULL, .guard = &g_4_12, .action = NULL, .target_state = &s_4_3} 
	 },
	 .transitions_count = 3
 };
 /** 404
  * Array to quickly access to a state by index
  */
 static fsm_state_t* s_4[4] = {&s_4_0, &s_4_1, &s_4_2, &s_4_3};
 /** 414
  * Create a new FSM for this rule
  */
 void *mmt_sec_create_new_fsm_4(){
		 return fsm_init( &s_4_0, &s_4_1, &s_4_2 );//init, error, final
 }//end function

 //======================================RULE 5======================================
 /** 475
  * Structure to represent event data
  */
 typedef struct _msg_struct_5{
	  const char *ip_dst;
	  const char *ip_src;
	  double tcp_flags;
	  uint64_t timestamp;//timestamp
	  uint64_t counter;//index of packet
 }_msg_t_5;
 /** 497
  * Create an instance of _msg_t_5
  */
 static inline _msg_t_5* _allocate_msg_t_5(){
	 _msg_t_5 *m = mmt_malloc( sizeof( _msg_t_5 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_flags = 0 ;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 523
  * Public API
  */
 void *mmt_sec_convert_message_to_event_5( const message_t *msg){
	 if( msg == NULL ) return NULL;
	 _msg_t_5 *new_msg = _allocate_msg_t_5( sizeof( _msg_t_5 ));
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i]->proto_id ){/** 533 For each protocol*/
		 case 178:// protocol ip
			 switch( msg->elements[i]->att_id ){
			 case 13:// attribute dst
				 new_msg->ip_dst = mmt_mem_retain( msg->elements[i]->data );
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = mmt_mem_retain( msg->elements[i]->data );
				 break;
			 }//end switch of att_id 540
			 break;
		 case 354:// protocol tcp
			 switch( msg->elements[i]->att_id ){
			 case 6:// attribute flags
				 new_msg->tcp_flags = *(double *)msg->elements[i]->data;
				 break;
			 }//end switch of att_id 559
		 }//end switch
	 }//end for
	 return (void *)new_msg; //562
 }//end function
 /** 435
  * Public API
  */
 void* mmt_sec_hash_message_5( const message_t *msg, uint32_t *tran_index){
	 _msg_t_5 *ev = mmt_malloc( sizeof( _msg_t_5 ));
	 size_t i;	 message_element_t *e;
	 for( i=0; i<msg->elements_count; i++){
		 e = msg->elements[i];
	 switch( e->proto_id ){
 /** 449
  * ip
  */
 	 case 178:
		 switch ( e->att_id){
		 case 13:	 //dst
			 return NULL;//0;
		 case 12:	 //src
			 return NULL;//1;
		 }//end att for 178
 /** 449
  * tcp
  */
 	 case 354:
		 switch ( e->att_id){
		 case 6:	 //flags
			 return NULL;//2;
		 }//last switch
	 }}
 return NULL; }
 /** 86
  * Rule 5, event 10
  * SYN request
  */
 static inline int g_5_10( void *condition, const fsm_event_t *event, const fsm_t *fsm ){
	 if( event->data == NULL ) return 0;
	 const _msg_t_5 *ev_data, *his_data;
	 ev_data = (_msg_t_5 *)event->data;/* 58 */
	 double tcp_flags = ev_data->tcp_flags;

	 return (tcp_flags == 2);
 }
 
 /** 86
  * Rule 5, event 11
  * SYN ACK replyyyyyy
  */
 static inline int g_5_11( void *condition, const fsm_event_t *event, const fsm_t *fsm ){
	 if( event->data == NULL ) return 0;
	 const _msg_t_5 *ev_data, *his_data;
	 ev_data = (_msg_t_5 *)event->data;
	 his_data = (_msg_t_5 *)fsm_get_history( fsm, 10);
	 if( his_data == NULL ) return 0;/* 58 */
	 const char *ip_dst_10 = his_data->ip_dst;
	 if( ip_dst_10 == NULL ) return 0;/* 58 */
	 const char *ip_src = ev_data->ip_src;
	 if( ip_src == NULL ) return 0;/* 58 */
	 double tcp_flags = ev_data->tcp_flags;

	 return ((tcp_flags == 18) && 0 == strcmp(ip_src , ip_dst_10));
 }
 
 /** 337
  * States of FSM for rule 5
  */
 
 /** 338
  * Predefine list of states: init, error, final, ...
  */
 static fsm_state_t s_5_0, s_5_1, s_5_2, s_5_3;
 /** 351
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 357
  * initial state
  */
  s_5_0 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 0.00, .counter_min = 0, .counter_max = 0},
	 .description  = "TCP SYN requests with SYN ACK.",
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = (fsm_transition_t[]){
		 /** 381 SYN request */
		 { .event_type = 0, .condition = NULL, .guard = &g_5_10, .action = NULL, .target_state = &s_5_3} 
	 },
	 .transitions_count = 1
 },
 /** 357
  * timeout/error state
  */
  s_5_1 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 0.00, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 357
  * final state
  */
  s_5_2 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 0.00, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 357
  * root node
  */
  s_5_3 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 1.00, .counter_min = 0, .counter_max = 0},
	 .description  = "TCP SYN requests with SYN ACK.",
	 .entry_action = 0,
	 .exit_action  = 1,
	 .transitions  = (fsm_transition_t[]){
		 { .event_type = 1, .condition = NULL, .guard = NULL  , .action = NULL, .target_state = &s_5_2},
		 /** 381 SYN ACK replyyyyyy */
		 { .event_type = 0, .condition = NULL, .guard = &g_5_11, .action = NULL, .target_state = &s_5_2},
		 /** 383 Loop to create a new instance */
		 { .event_type = 0, .condition = NULL, .guard = &g_5_10, .action = NULL, .target_state = &s_5_3} 
	 },
	 .transitions_count = 3
 };
 /** 404
  * Array to quickly access to a state by index
  */
 static fsm_state_t* s_5[4] = {&s_5_0, &s_5_1, &s_5_2, &s_5_3};
 /** 414
  * Create a new FSM for this rule
  */
 void *mmt_sec_create_new_fsm_5(){
		 return fsm_init( &s_5_0, &s_5_1, &s_5_2 );//init, error, final
 }//end function

 //======================================RULE 6======================================
 /** 475
  * Structure to represent event data
  */
 typedef struct _msg_struct_6{
	  const char *http_method;
	  const char *http_user_agent;
	  uint64_t timestamp;//timestamp
	  uint64_t counter;//index of packet
 }_msg_t_6;
 /** 497
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
 /** 523
  * Public API
  */
 void *mmt_sec_convert_message_to_event_6( const message_t *msg){
	 if( msg == NULL ) return NULL;
	 _msg_t_6 *new_msg = _allocate_msg_t_6( sizeof( _msg_t_6 ));
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i]->proto_id ){/** 533 For each protocol*/
		 case 153:// protocol http
			 switch( msg->elements[i]->att_id ){
			 case 1:// attribute method
				 new_msg->http_method = mmt_mem_retain( msg->elements[i]->data );
				 break;
			 case 7:// attribute user_agent
				 new_msg->http_user_agent = mmt_mem_retain( msg->elements[i]->data );
				 break;
			 }//end switch of att_id 559
		 }//end switch
	 }//end for
	 return (void *)new_msg; //562
 }//end function
 /** 435
  * Public API
  */
 void* mmt_sec_hash_message_6( const message_t *msg, uint32_t *tran_index){
	 _msg_t_6 *ev = mmt_malloc( sizeof( _msg_t_6 ));
	 size_t i;	 message_element_t *e;
	 for( i=0; i<msg->elements_count; i++){
		 e = msg->elements[i];
	 switch( e->proto_id ){
 /** 449
  * http
  */
 	 case 153:
		 switch ( e->att_id){
		 case 1:	 //method
			 return NULL;//0;
		 case 7:	 //user_agent
			 return NULL;//1;
		 }//last switch
	 }}
 return NULL; }
 /** 86
  * Rule 6, event 1
  * Having GET request
  */
 static inline int g_6_1( void *condition, const fsm_event_t *event, const fsm_t *fsm ){
	 if( event->data == NULL ) return 0;
	 const _msg_t_6 *ev_data, *his_data;
	 ev_data = (_msg_t_6 *)event->data;/* 58 */
	 const char *http_method = ev_data->http_method;
	 if( http_method == NULL ) return 0;

	 return 0 == strcmp(http_method , "GET");
 }
 
 /** 86
  * Rule 6, event 2
  * Must have User-Agent
  */
 static inline int g_6_2( void *condition, const fsm_event_t *event, const fsm_t *fsm ){
	 if( event->data == NULL ) return 0;
	 const _msg_t_6 *ev_data, *his_data;
	 ev_data = (_msg_t_6 *)event->data;/* 58 */
	 const char *http_user_agent = ev_data->http_user_agent;
	 if( http_user_agent == NULL ) return 0;

	 return 0 != strcmp(http_user_agent , "phantom");
 }
 
 /** 337
  * States of FSM for rule 6
  */
 
 /** 338
  * Predefine list of states: init, error, final, ...
  */
 static fsm_state_t s_6_0, s_6_1, s_6_2, s_6_3;
 /** 351
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 357
  * initial state
  */
  s_6_0 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 0.00, .counter_min = 0, .counter_max = 0},
	 .description  = "Get request from ghost",
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = (fsm_transition_t[]){
		 /** 381 Having GET request */
		 { .event_type = 0, .condition = NULL, .guard = &g_6_1, .action = NULL, .target_state = &s_6_3} 
	 },
	 .transitions_count = 1
 },
 /** 357
  * timeout/error state
  */
  s_6_1 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 0.00, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 357
  * final state
  */
  s_6_2 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 0.00, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0,
	 .exit_action  = 0,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 357
  * root node
  */
  s_6_3 = {
	 .timer        = 0,
	 .counter      = 0,
	 .delay        = {.time_min = 0.00, .time_max = 1.00, .counter_min = 0, .counter_max = 0},
	 .description  = "Get request from ghost",
	 .entry_action = 0,
	 .exit_action  = 1,
	 .transitions  = (fsm_transition_t[]){
		 { .event_type = 1, .condition = NULL, .guard = NULL  , .action = NULL, .target_state = &s_6_2},
		 /** 381 Must have User-Agent */
		 { .event_type = 0, .condition = NULL, .guard = &g_6_2, .action = NULL, .target_state = &s_6_2},
		 /** 383 Loop to create a new instance */
		 { .event_type = 0, .condition = NULL, .guard = &g_6_1, .action = NULL, .target_state = &s_6_3} 
	 },
	 .transitions_count = 3
 };
 /** 404
  * Array to quickly access to a state by index
  */
 static fsm_state_t* s_6[4] = {&s_6_0, &s_6_1, &s_6_2, &s_6_3};
 /** 414
  * Create a new FSM for this rule
  */
 void *mmt_sec_create_new_fsm_6(){
		 return fsm_init( &s_6_0, &s_6_1, &s_6_2 );//init, error, final
 }//end function

 //======================================GENERAL======================================
 /** 575
  * Information of 6 rules
  */
 size_t mmt_sec_get_plugin_info( const rule_info_t **rules_arr ){
	  static const rule_info_t rules[] = (rule_info_t[]){
		 {
			 .id               = 1,
			 .description      = "Several attempts to connect via ssh (brute force attack). Source address is either infected machine or attacker (no spoofing is possible).",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &mmt_sec_create_new_fsm_1,
			 .hash_message     = NULL,//&mmt_sec_hash_message_1,
			 .convert_message  = &mmt_sec_convert_message_to_event_1
		 },
		 {
			 .id               = 2,
			 .description      = "Attempted to connect via ssh but reseted immediately. Source address is either infected machine or attacker (no spoofing is possible).",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &mmt_sec_create_new_fsm_2,
			 .hash_message     = NULL,//&mmt_sec_hash_message_2,
			 .convert_message  = &mmt_sec_convert_message_to_event_2
		 },
		 {
			 .id               = 3,
			 .description      = "TCP SYN requests on microsoft-ds port 445 with SYN ACK.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &mmt_sec_create_new_fsm_3,
			 .hash_message     = NULL,//&mmt_sec_hash_message_3,
			 .convert_message  = &mmt_sec_convert_message_to_event_3
		 },
		 {
			 .id               = 4,
			 .description      = "Two successive TCP SYN requests but with different destnation addresses.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &mmt_sec_create_new_fsm_4,
			 .hash_message     = NULL,//&mmt_sec_hash_message_4,
			 .convert_message  = &mmt_sec_convert_message_to_event_4
		 },
		 {
			 .id               = 5,
			 .description      = "TCP SYN requests with SYN ACK.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = "py_createstix(4_TCP_SYN_request_without_SYN_ACK_could_be_a_spoofed_address, ip.src.10)",
			 .create_instance  = &mmt_sec_create_new_fsm_5,
			 .hash_message     = NULL,//&mmt_sec_hash_message_5,
			 .convert_message  = &mmt_sec_convert_message_to_event_5
		 },
		 {
			 .id               = 6,
			 .description      = "Get request from ghost",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &mmt_sec_create_new_fsm_6,
			 .hash_message     = NULL,//&mmt_sec_hash_message_6,
			 .convert_message  = &mmt_sec_convert_message_to_event_6
		 }
	 };
	 *rules_arr = rules;
	 return 6;
 }
