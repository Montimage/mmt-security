
 /** 926
  * This file is generated automatically on 2017-02-16 10:52:34
  */
 #include <string.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include "plugin_header.h"
 #include "mmt_fsm.h"
 #include "mmt_lib.h"
 
 /** 933
  * Embedded functions
  */
 

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

static inline int check_sql_injection(const void *p_payload, double payload_len){
   int key_word_len = 6;
   char *key_words[6] = {"DROP", "UNION", "SELECT", "CHAR", "DELETE", "INSERT"};
   size_t len = payload_len, i;
   char *str  = malloc( len + 1 );
   memcpy( str, p_payload, len );
   str[ len ] = '\0';
   //Signature based dection begin here. 
   //(using  pattern matching techniques against signatures and 
   //keyword-based stores to identify potentially malicious requests)
   for( i=0; i<key_word_len; i++)
      if( strstr(str, key_words[i]  ) != NULL ){
         free( str );
         return 1;
      }
   
   free( str );
   return 0;
}




 //======================================RULE 16======================================
 #define EVENTS_COUNT_16 2

 #define PROTO_ATTS_COUNT_16 4

 /** 866
  * Proto_atts for rule 16
  */
 
 static proto_attribute_t proto_atts_16[ PROTO_ATTS_COUNT_16 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "p_payload", .att_id = 4098, .data_type = 2}, {.proto = "tcp", .proto_id = 354, .att = "payload_len", .att_id = 23, .data_type = 0}};
 /** 878
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_16[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_16[ 2 ] ,  &proto_atts_16[ 3 ] }
	 },
	 {//event_2
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_16[ 0 ] ,  &proto_atts_16[ 1 ] }
	 } 
 };//end proto_atts_events_

 /** 555
  * Structure to represent event data
  */
 typedef struct _msg_struct_16{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const char *ip_src;
	 const void *tcp_p_payload;
	 const double *tcp_payload_len;
 }_msg_t_16;
 /** 591
  * Create an instance of _msg_t_16
  */
 static inline _msg_t_16* _allocate_msg_t_16(){
	 static _msg_t_16 _msg;
	 _msg_t_16 *m = &_msg;
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_p_payload = NULL;
	 m->tcp_payload_len = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static const void *convert_message_to_event_16( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_16 *new_msg = _allocate_msg_t_16();
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
			 case 4098:// attribute p_payload
				 new_msg->tcp_p_payload = (void *) msg->elements[i].data;
				 break;
			 case 23:// attribute payload_len
				 new_msg->tcp_payload_len = (double *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 522
  * Public API
  */
 static uint64_t hash_message_16( const void *data ){
	 uint64_t hash = 0;
	 size_t i;	 _msg_t_16 *msg = (_msg_t_16 *) data;
	 //if( msg == NULL ) return hash;

	 if( msg->tcp_p_payload != NULL && msg->tcp_payload_len != NULL )
		 hash  |= 2; //event_id = 1
	 if( msg->ip_dst != NULL && msg->ip_src != NULL )
		 hash  |= 4; //event_id = 2
	 return hash;
 }
 /** 94
  * Rule 16, event 1
  * Context: Here it is a TCP segment
  */
 static inline int g_16_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_16 *his_data, *ev_data = (_msg_t_16 *) event_data;/* 61 */
	 if( unlikely( ev_data->tcp_p_payload == NULL )) return 0;
	 const void *tcp_p_payload =  ev_data->tcp_p_payload ;/* 61 */
	 if( unlikely( ev_data->tcp_payload_len == NULL )) return 0;
	 double tcp_payload_len = *( ev_data->tcp_payload_len );

	 return ((tcp_payload_len > 0) && (check_sql_injection(tcp_p_payload , tcp_payload_len) == 1));
 }
 
 /** 94
  * Rule 16, event 2
  * Trigger: SQL Injection in the payload
  */
 static inline int g_16_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_16 *his_data, *ev_data = (_msg_t_16 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return 0 != mmt_mem_cmp(ip_src , ip_dst);
 }
 
 /** 411
  * States of FSM for rule 16
  */
 
 /** 412
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_16_0, s_16_1, s_16_2, s_16_3, s_16_4;
 /** 425
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 431
  * initial state
  */
  s_16_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "SQL Injection detected",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 460 Context: Here it is a TCP segment */
		 /** 462 A real event */
		 { .event_type = 1, .guard = &g_16_1, .action = 1, .target_state = &s_16_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 431
  * timeout/error state
  */
  s_16_1 = {
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
  s_16_2 = {
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
  s_16_3 = {
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
  s_16_4 = {
	 .delay        = {.time_min = 0LL, .time_max = 0LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 1,
	 .description  = "SQL Injection detected",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 462 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_16_1}, //FSM_ACTION_DO_NOTHING
		 /** 460 Trigger: SQL Injection in the payload */
		 /** 462 A real event */
		 { .event_type = 2, .guard = &g_16_2, .action = 2, .target_state = &s_16_2}  //FSM_ACTION_RESET_TIMER
	 },
	 .transitions_count = 2
 };
 /** 489
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_16(){
		 return fsm_init( &s_16_0, &s_16_1, &s_16_2, &s_16_3, EVENTS_COUNT_16, sizeof( _msg_t_16 ) );//init, error, final, inconclusive, events_count
 }//end function

 //======================================GENERAL======================================
 /** 666
  * Information of 1 rules
  * PUBLIC API
  */
 size_t mmt_sec_get_plugin_info( const rule_info_t **rules_arr ){
	  static const rule_info_t rules[] = (rule_info_t[]){
		 {
			 .id               = 16,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_16,
			 .proto_atts_count = PROTO_ATTS_COUNT_16,
			 .proto_atts       = proto_atts_16,
			 .proto_atts_events= proto_atts_events_16,
			 .description      = "SQL Injection detected",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_16,
			 .hash_message     = &hash_message_16,
			 .convert_message  = &convert_message_to_event_16,
			 .message_size     = sizeof( _msg_t_16 )
		 }
	 };
	 *rules_arr = rules;
	 return 1;
 }
 /** 696
  * Moment the rules being encoded
  * PUBLIC API
  */
 const char * __get_generated_date(){ return "2017-02-16 10:52:34, mmt-security version 1.0.0 (9a0c0f6)";};