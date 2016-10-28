
 /** 692
  * This file is generated automatically on 2016-10-28 17:40:17
  */
 #include <string.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include "plugin_header.h"
 #include "mmt_fsm.h"
 #include "mmt_alloc.h"
 

 //======================================RULE 10======================================
 #define EVENTS_COUNT_10 3

 #define PROTO_ATTS_COUNT_10 4

 static proto_attribute_t proto_atts_10[ PROTO_ATTS_COUNT_10 ] = {{.proto = "arp", .proto_id = 30, .att = "ar_op", .att_id = 5, .data_type = 0}, {.proto = "arp", .proto_id = 30, .att = "ar_sha", .att_id = 6, .data_type = 1}, {.proto = "arp", .proto_id = 30, .att = "ar_sip", .att_id = 7, .data_type = 1}, {.proto = "arp", .proto_id = 30, .att = "ar_tip", .att_id = 9, .data_type = 1}};

 /** 481
  * Structure to represent event data
  */
 typedef struct _msg_struct_10{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const double *arp_ar_op;
	 const char *arp_ar_sha;
	 const char *arp_ar_sip;
	 const char *arp_ar_tip;
 }_msg_t_10;
 /** 516
  * Create an instance of _msg_t_10
  */
 static inline _msg_t_10* _allocate_msg_t_10(){
	 _msg_t_10 *m = mmt_mem_alloc( sizeof( _msg_t_10 ));
	 m->arp_ar_op = NULL;
	 m->arp_ar_sha = NULL;
	 m->arp_ar_sip = NULL;
	 m->arp_ar_tip = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 540
  * Public API
  */
 static void *convert_message_to_event_10( const message_t *msg){
	 if( msg == NULL ) return NULL;
	 _msg_t_10 *new_msg = _allocate_msg_t_10( sizeof( _msg_t_10 ));
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i].proto_id ){/** 550 For each protocol*/
		 case 30:// protocol arp
			 switch( msg->elements[i].att_id ){
			 case 5:// attribute ar_op
				 new_msg->arp_ar_op = (double *) msg->elements[i].data;
				 break;
			 case 6:// attribute ar_sha
				 new_msg->arp_ar_sha = (char *) msg->elements[i].data;
				 break;
			 case 7:// attribute ar_sip
				 new_msg->arp_ar_sip = (char *) msg->elements[i].data;
				 break;
			 case 9:// attribute ar_tip
				 new_msg->arp_ar_tip = (char *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 574
		 }//end switch
	 }//end for
	 return (void *)new_msg; //577
 }//end function
 /** 446
  * Public API
  */
 static const uint16_t* hash_message_10( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_10 ];
	 size_t i;	 _msg_t_10 *msg = (_msg_t_10 *) data;
	 for( i=0; i<EVENTS_COUNT_10; i++) hash_table[i] = 0;/** 452 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;
	 if( msg->arp_ar_op != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->arp_ar_op != NULL && msg->arp_ar_sip != NULL && msg->arp_ar_tip != NULL )
		 hash_table[ 1 ] = 2;
	 if( msg->arp_ar_op != NULL && msg->arp_ar_sha != NULL && msg->arp_ar_sip != NULL && msg->arp_ar_tip != NULL )
		 hash_table[ 2 ] = 3;
	 return hash_table;
 }
 /** 92
  * Rule 10, event 1
  * An arp who was requested
  */
 static inline int g_10_1( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_10 *his_data, *ev_data = (_msg_t_10 *) event_data;/* 63 */
	 double arp_ar_op = *( ev_data->arp_ar_op );

	 return (arp_ar_op == 1);
 }
 
 /** 92
  * Rule 10, event 2
  * An arp reply with MAC address
  */
 static inline int g_10_2( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_10 *his_data, *ev_data = (_msg_t_10 *) event_data;/* 63 */
	 double arp_ar_op = *( ev_data->arp_ar_op );/* 63 */
	 const char *arp_ar_sip =  ev_data->arp_ar_sip ;
	 his_data = (_msg_t_10 *)fsm_get_history( fsm, 1);/* 63 */
	 const char *arp_ar_tip_1 =  his_data->arp_ar_tip ;

	 return ((arp_ar_op == 2) && 0 == strcmp(arp_ar_sip , arp_ar_tip_1));
 }
 
 /** 92
  * Rule 10, event 3
  * An arp reply but with different MAC address
  */
 static inline int g_10_3( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_10 *his_data, *ev_data = (_msg_t_10 *) event_data;/* 63 */
	 double arp_ar_op = *( ev_data->arp_ar_op );
	 his_data = (_msg_t_10 *)fsm_get_history( fsm, 2);/* 63 */
	 const char *arp_ar_sha_2 =  his_data->arp_ar_sha ;/* 63 */
	 const char *arp_ar_sha =  ev_data->arp_ar_sha ;/* 63 */
	 const char *arp_ar_sip =  ev_data->arp_ar_sip ;
	 his_data = (_msg_t_10 *)fsm_get_history( fsm, 1);/* 63 */
	 const char *arp_ar_tip_1 =  his_data->arp_ar_tip ;

	 return (((arp_ar_op == 2) && 0 == strcmp(arp_ar_sip , arp_ar_tip_1)) && 0 != strcmp(arp_ar_sha , arp_ar_sha_2));
 }
 
 /** 332
  * States of FSM for rule 10
  */
 
 /** 333
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_10_0, s_10_1, s_10_2, s_10_3, s_10_4, s_10_5;
 /** 346
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 352
  * initial state
  */
  s_10_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  = "IPv4 address conflict detection (RFC5227). Possible arp poisoning.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 377 An arp who was requested */
		 /** 379 A real event */
		 { .event_type = 1, .guard = &g_10_1, .action = 1, .target_state = &s_10_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 352
  * timeout/error state
  */
  s_10_1 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 352
  * final state
  */
  s_10_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_10_3 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_10_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 300000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 379 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_10_3}, //FSM_ACTION_DO_NOTHING
		 /** 377 An arp reply with MAC address */
		 /** 379 A real event */
		 { .event_type = 2, .guard = &g_10_2, .action = 1, .target_state = &s_10_5}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 2
 },
 /** 352
  * root node
  */
  s_10_5 = {
	 .delay        = {.time_min = 1LL, .time_max = 300000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .description  = "IPv4 address conflict detection (RFC5227). Possible arp poisoning.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 379 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_10_1}, //FSM_ACTION_DO_NOTHING
		 /** 377 An arp reply but with different MAC address */
		 /** 379 A real event */
		 { .event_type = 3, .guard = &g_10_3, .action = 0, .target_state = &s_10_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 414
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_10(){
		 return fsm_init( &s_10_0, &s_10_1, &s_10_2, &s_10_3 );//init, error, final, inconclusive
 }//end function

 //======================================RULE 12======================================
 #define EVENTS_COUNT_12 2

 #define PROTO_ATTS_COUNT_12 3

 static proto_attribute_t proto_atts_12[ PROTO_ATTS_COUNT_12 ] = {{.proto = "arp", .proto_id = 30, .att = "ar_op", .att_id = 5, .data_type = 0}, {.proto = "arp", .proto_id = 30, .att = "ar_sha", .att_id = 6, .data_type = 1}, {.proto = "arp", .proto_id = 30, .att = "ar_sip", .att_id = 7, .data_type = 1}};

 /** 481
  * Structure to represent event data
  */
 typedef struct _msg_struct_12{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const double *arp_ar_op;
	 const char *arp_ar_sha;
	 const char *arp_ar_sip;
 }_msg_t_12;
 /** 516
  * Create an instance of _msg_t_12
  */
 static inline _msg_t_12* _allocate_msg_t_12(){
	 _msg_t_12 *m = mmt_mem_alloc( sizeof( _msg_t_12 ));
	 m->arp_ar_op = NULL;
	 m->arp_ar_sha = NULL;
	 m->arp_ar_sip = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 540
  * Public API
  */
 static void *convert_message_to_event_12( const message_t *msg){
	 if( msg == NULL ) return NULL;
	 _msg_t_12 *new_msg = _allocate_msg_t_12( sizeof( _msg_t_12 ));
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i].proto_id ){/** 550 For each protocol*/
		 case 30:// protocol arp
			 switch( msg->elements[i].att_id ){
			 case 5:// attribute ar_op
				 new_msg->arp_ar_op = (double *) msg->elements[i].data;
				 break;
			 case 6:// attribute ar_sha
				 new_msg->arp_ar_sha = (char *) msg->elements[i].data;
				 break;
			 case 7:// attribute ar_sip
				 new_msg->arp_ar_sip = (char *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 574
		 }//end switch
	 }//end for
	 return (void *)new_msg; //577
 }//end function
 /** 446
  * Public API
  */
 static const uint16_t* hash_message_12( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_12 ];
	 size_t i;	 _msg_t_12 *msg = (_msg_t_12 *) data;
	 for( i=0; i<EVENTS_COUNT_12; i++) hash_table[i] = 0;/** 452 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;
	 if( msg->arp_ar_op != NULL )
		 hash_table[ 0 ] = 4;
	 if( msg->arp_ar_op != NULL && msg->arp_ar_sha != NULL && msg->arp_ar_sip != NULL )
		 hash_table[ 1 ] = 5;
	 return hash_table;
 }
 /** 92
  * Rule 12, event 4
  * An arp reply with MAC address
  */
 static inline int g_12_4( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_12 *his_data, *ev_data = (_msg_t_12 *) event_data;/* 63 */
	 double arp_ar_op = *( ev_data->arp_ar_op );

	 return (arp_ar_op == 2);
 }
 
 /** 92
  * Rule 12, event 5
  * An arp reply but with different MAC address
  */
 static inline int g_12_5( const void *event_data, const fsm_t *fsm ){
	 if( event_data == NULL ) return 0;
	 const _msg_t_12 *his_data, *ev_data = (_msg_t_12 *) event_data;/* 63 */
	 double arp_ar_op = *( ev_data->arp_ar_op );
	 his_data = (_msg_t_12 *)fsm_get_history( fsm, 4);/* 63 */
	 const char *arp_ar_sha_4 =  his_data->arp_ar_sha ;/* 63 */
	 const char *arp_ar_sha =  ev_data->arp_ar_sha ;
	 his_data = (_msg_t_12 *)fsm_get_history( fsm, 4);/* 63 */
	 const char *arp_ar_sip_4 =  his_data->arp_ar_sip ;/* 63 */
	 const char *arp_ar_sip =  ev_data->arp_ar_sip ;

	 return (((arp_ar_op == 2) && 0 == strcmp(arp_ar_sip , arp_ar_sip_4)) && 0 != strcmp(arp_ar_sha , arp_ar_sha_4));
 }
 
 /** 332
  * States of FSM for rule 12
  */
 
 /** 333
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_12_0, s_12_1, s_12_2, s_12_3, s_12_4;
 /** 346
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 352
  * initial state
  */
  s_12_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  = "IPv4 address conflict detection (RFC5227). Possible arp poisoning.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 377 An arp reply with MAC address */
		 /** 379 A real event */
		 { .event_type = 4, .guard = &g_12_4, .action = 1, .target_state = &s_12_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 352
  * timeout/error state
  */
  s_12_1 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 352
  * final state
  */
  s_12_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_12_3 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 352
  * root node
  */
  s_12_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 300000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .description  = "IPv4 address conflict detection (RFC5227). Possible arp poisoning.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 379 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_12_1}, //FSM_ACTION_DO_NOTHING
		 /** 377 An arp reply but with different MAC address */
		 /** 379 A real event */
		 { .event_type = 5, .guard = &g_12_5, .action = 0, .target_state = &s_12_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 414
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_12(){
		 return fsm_init( &s_12_0, &s_12_1, &s_12_2, &s_12_3 );//init, error, final, inconclusive
 }//end function

 //======================================GENERAL======================================
 /** 590
  * Information of 2 rules
  */
 size_t mmt_sec_get_plugin_info( const rule_info_t **rules_arr ){
	  static const rule_info_t rules[] = (rule_info_t[]){
		 {
			 .id               = 10,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_10,
			 .proto_atts_count = PROTO_ATTS_COUNT_10,
			 .proto_atts       = proto_atts_10,
			 .description      = "IPv4 address conflict detection (RFC5227). Possible arp poisoning.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_10,
			 .hash_message     = &hash_message_10,
			 .convert_message  = &convert_message_to_event_10
		 },
		 {
			 .id               = 12,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_12,
			 .proto_atts_count = PROTO_ATTS_COUNT_12,
			 .proto_atts       = proto_atts_12,
			 .description      = "IPv4 address conflict detection (RFC5227). Possible arp poisoning.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_12,
			 .hash_message     = &hash_message_12,
			 .convert_message  = &convert_message_to_event_12
		 }
	 };
	 *rules_arr = rules;
	 return 2;
 }