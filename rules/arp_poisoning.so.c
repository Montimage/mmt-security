
 /** 835
  * This file is generated automatically on 2017-04-13 18:41:50
  */
 #include <string.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include "plugin_header.h"
 #include "mmt_fsm.h"
 #include "mmt_lib.h"
 
 /** 842
  * Embedded functions
  */
 

 //======================================RULE 1======================================
 #define EVENTS_COUNT_1 3

 #define PROTO_ATTS_COUNT_1 4

 /** 779
  * Proto_atts for rule 1
  */
 
 static proto_attribute_t proto_atts_1[ PROTO_ATTS_COUNT_1 ] = {{.proto = "arp", .proto_id = 30, .att = "ar_op", .att_id = 5, .data_type = 0, .dpi_type = 2},
 {.proto = "arp", .proto_id = 30, .att = "ar_sha", .att_id = 6, .data_type = 1, .dpi_type = 6},
 {.proto = "arp", .proto_id = 30, .att = "ar_sip", .att_id = 7, .data_type = 1, .dpi_type = 8},
 {.proto = "arp", .proto_id = 30, .att = "ar_tip", .att_id = 9, .data_type = 1, .dpi_type = 8}};
 /** 791
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_1[ 4 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_1[ 0 ] ,  &proto_atts_1[ 3 ] }
	 },
	 {//event_2
		 .elements_count = 3,
		 .data = (void* []) { &proto_atts_1[ 0 ] ,  &proto_atts_1[ 1 ] ,  &proto_atts_1[ 2 ] }
	 },
	 {//event_3
		 .elements_count = 3,
		 .data = (void* []) { &proto_atts_1[ 0 ] ,  &proto_atts_1[ 1 ] ,  &proto_atts_1[ 2 ] }
	 } 
 };//end proto_atts_events_

 /** 522
  * Structure to represent event data
  */
 typedef struct _msg_struct_1{
	 uint16_t _arp__ar_op;
	 uint16_t _arp__ar_sha;
	 uint16_t _arp__ar_sip;
	 uint16_t _arp__ar_tip;
 }_msg_t_1;
 /** 556
  * Create an instance of _msg_t_1
  */
 static _msg_t_1 _m_index_1;
 static void _allocate_msg_t_1( const char* proto, const char* att, uint16_t index ){
	 if( strcmp( proto, "arp" ) == 0 && strcmp( att, "ar_op" ) == 0 ){ _m_index_1._arp__ar_op = index; return; }
	 if( strcmp( proto, "arp" ) == 0 && strcmp( att, "ar_sha" ) == 0 ){ _m_index_1._arp__ar_sha = index; return; }
	 if( strcmp( proto, "arp" ) == 0 && strcmp( att, "ar_sip" ) == 0 ){ _m_index_1._arp__ar_sip = index; return; }
	 if( strcmp( proto, "arp" ) == 0 && strcmp( att, "ar_tip" ) == 0 ){ _m_index_1._arp__ar_tip = index; return; }
 }
 /** 97
  * Rule 1, event 1
  * An arp who was requested
  */
 static inline int g_1_1( const message_t *msg, const fsm_t *fsm ){
	 if( unlikely( msg == NULL || fsm == NULL )) return 0;
	 const message_t *his_msg;
	 const void *data;/* 63 */

	 data = get_element_data_message_t( msg, _m_index_1._arp__ar_op );
	 if( unlikely( data == NULL )) return 0;
	 double arp_ar_op = *(double*)  data;

	 return (arp_ar_op == 1);
 }
 
 /** 97
  * Rule 1, event 2
  * An arp reply with MAC address
  */
 static inline int g_1_2( const message_t *msg, const fsm_t *fsm ){
	 if( unlikely( msg == NULL || fsm == NULL )) return 0;
	 const message_t *his_msg;
	 const void *data;/* 63 */

	 data = get_element_data_message_t( msg, _m_index_1._arp__ar_op );
	 if( unlikely( data == NULL )) return 0;
	 double arp_ar_op = *(double*)  data;/* 63 */

	 data = get_element_data_message_t( msg, _m_index_1._arp__ar_sip );
	 if( unlikely( data == NULL )) return 0;
	 const char *arp_ar_sip = (char *) data;
	 his_msg = fsm_get_history( fsm, 1 );
	 if( unlikely( his_msg == NULL )) return 0;/* 63 */

	 data = get_element_data_message_t( his_msg, _m_index_1._arp__ar_tip );
	 if( unlikely( data == NULL )) return 0;
	 const char *arp_ar_tip_1 = (char *) data;

	 return ((arp_ar_op == 2) && 0 == mmt_mem_cmp(arp_ar_sip , arp_ar_tip_1));
 }
 
 /** 97
  * Rule 1, event 3
  * An arp reply but with different MAC address
  */
 static inline int g_1_3( const message_t *msg, const fsm_t *fsm ){
	 if( unlikely( msg == NULL || fsm == NULL )) return 0;
	 const message_t *his_msg;
	 const void *data;/* 63 */

	 data = get_element_data_message_t( msg, _m_index_1._arp__ar_op );
	 if( unlikely( data == NULL )) return 0;
	 double arp_ar_op = *(double*)  data;
	 his_msg = fsm_get_history( fsm, 2 );
	 if( unlikely( his_msg == NULL )) return 0;/* 63 */

	 data = get_element_data_message_t( his_msg, _m_index_1._arp__ar_sha );
	 if( unlikely( data == NULL )) return 0;
	 const char *arp_ar_sha_2 = (char *) data;/* 63 */

	 data = get_element_data_message_t( msg, _m_index_1._arp__ar_sha );
	 if( unlikely( data == NULL )) return 0;
	 const char *arp_ar_sha = (char *) data;/* 63 */

	 data = get_element_data_message_t( msg, _m_index_1._arp__ar_sip );
	 if( unlikely( data == NULL )) return 0;
	 const char *arp_ar_sip = (char *) data;/* 63 */

	 data = get_element_data_message_t( his_msg, _m_index_1._arp__ar_tip );
	 if( unlikely( data == NULL )) return 0;
	 const char *arp_ar_tip_1 = (char *) data;

	 return (((arp_ar_op == 2) && 0 == mmt_mem_cmp(arp_ar_sip , arp_ar_tip_1)) && 0 != mmt_mem_cmp(arp_ar_sha , arp_ar_sha_2));
 }
 
 /** 415
  * States of FSM for rule 1
  */
 
 /** 416
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_1_0, s_1_1, s_1_2, s_1_3, s_1_4, s_1_5;
 /** 429
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 435
  * initial state
  */
  s_1_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,
	 .description  = "IPv4 address conflict detection (RFC5227). Possible arp poisoning.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .transitions  = (fsm_transition_t[]){
		 /** 463 An arp who was requested */
		 /** 465 A real event */
		 { .event_type = 1, .guard = &g_1_1, .action = 1, .target_state = &s_1_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 435
  * timeout/error state
  */
  s_1_1 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 435
  * pass state
  */
  s_1_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 435
  * inconclusive state
  */
  s_1_3 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_1_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 300000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .transitions  = (fsm_transition_t[]){
		 /** 465 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_1_3}, //FSM_ACTION_DO_NOTHING
		 /** 463 An arp reply with MAC address */
		 /** 465 A real event */
		 { .event_type = 2, .guard = &g_1_2, .action = 2, .target_state = &s_1_5}  //FSM_ACTION_RESET_TIMER
	 },
	 .transitions_count = 2
 },
 /** 435
  * root node
  */
  s_1_5 = {
	 .delay        = {.time_min = 1LL, .time_max = 300000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  = "IPv4 address conflict detection (RFC5227). Possible arp poisoning.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .transitions  = (fsm_transition_t[]){
		 /** 465 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_1_1}, //FSM_ACTION_DO_NOTHING
		 /** 463 An arp reply but with different MAC address */
		 /** 465 A real event */
		 { .event_type = 3, .guard = &g_1_3, .action = 2, .target_state = &s_1_2}  //FSM_ACTION_RESET_TIMER
	 },
	 .transitions_count = 2
 };
 /** 492
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_1(){
		 return fsm_init( &s_1_0, &s_1_1, &s_1_2, &s_1_3, EVENTS_COUNT_1, sizeof( _msg_t_1 ) );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 2======================================
 #define EVENTS_COUNT_2 2

 #define PROTO_ATTS_COUNT_2 3

 /** 779
  * Proto_atts for rule 2
  */
 
 static proto_attribute_t proto_atts_2[ PROTO_ATTS_COUNT_2 ] = {{.proto = "arp", .proto_id = 30, .att = "ar_op", .att_id = 5, .data_type = 0, .dpi_type = 2},
 {.proto = "arp", .proto_id = 30, .att = "ar_sha", .att_id = 6, .data_type = 1, .dpi_type = 6},
 {.proto = "arp", .proto_id = 30, .att = "ar_sip", .att_id = 7, .data_type = 1, .dpi_type = 8}};
 /** 791
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_2[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 3,
		 .data = (void* []) { &proto_atts_2[ 0 ] ,  &proto_atts_2[ 1 ] ,  &proto_atts_2[ 2 ] }
	 },
	 {//event_2
		 .elements_count = 3,
		 .data = (void* []) { &proto_atts_2[ 0 ] ,  &proto_atts_2[ 1 ] ,  &proto_atts_2[ 2 ] }
	 } 
 };//end proto_atts_events_

 /** 522
  * Structure to represent event data
  */
 typedef struct _msg_struct_2{
	 uint16_t _arp__ar_op;
	 uint16_t _arp__ar_sha;
	 uint16_t _arp__ar_sip;
 }_msg_t_2;
 /** 556
  * Create an instance of _msg_t_2
  */
 static _msg_t_2 _m_index_2;
 static void _allocate_msg_t_2( const char* proto, const char* att, uint16_t index ){
	 if( strcmp( proto, "arp" ) == 0 && strcmp( att, "ar_op" ) == 0 ){ _m_index_2._arp__ar_op = index; return; }
	 if( strcmp( proto, "arp" ) == 0 && strcmp( att, "ar_sha" ) == 0 ){ _m_index_2._arp__ar_sha = index; return; }
	 if( strcmp( proto, "arp" ) == 0 && strcmp( att, "ar_sip" ) == 0 ){ _m_index_2._arp__ar_sip = index; return; }
 }
 /** 97
  * Rule 2, event 1
  * An arp reply with MAC address
  */
 static inline int g_2_1( const message_t *msg, const fsm_t *fsm ){
	 if( unlikely( msg == NULL || fsm == NULL )) return 0;
	 const message_t *his_msg;
	 const void *data;/* 63 */

	 data = get_element_data_message_t( msg, _m_index_2._arp__ar_op );
	 if( unlikely( data == NULL )) return 0;
	 double arp_ar_op = *(double*)  data;

	 return (arp_ar_op == 2);
 }
 
 /** 97
  * Rule 2, event 2
  * An arp reply but with different MAC address
  */
 static inline int g_2_2( const message_t *msg, const fsm_t *fsm ){
	 if( unlikely( msg == NULL || fsm == NULL )) return 0;
	 const message_t *his_msg;
	 const void *data;/* 63 */

	 data = get_element_data_message_t( msg, _m_index_2._arp__ar_op );
	 if( unlikely( data == NULL )) return 0;
	 double arp_ar_op = *(double*)  data;
	 his_msg = fsm_get_history( fsm, 1 );
	 if( unlikely( his_msg == NULL )) return 0;/* 63 */

	 data = get_element_data_message_t( his_msg, _m_index_2._arp__ar_sha );
	 if( unlikely( data == NULL )) return 0;
	 const char *arp_ar_sha_1 = (char *) data;/* 63 */

	 data = get_element_data_message_t( msg, _m_index_2._arp__ar_sha );
	 if( unlikely( data == NULL )) return 0;
	 const char *arp_ar_sha = (char *) data;/* 63 */

	 data = get_element_data_message_t( his_msg, _m_index_2._arp__ar_sip );
	 if( unlikely( data == NULL )) return 0;
	 const char *arp_ar_sip_1 = (char *) data;/* 63 */

	 data = get_element_data_message_t( msg, _m_index_2._arp__ar_sip );
	 if( unlikely( data == NULL )) return 0;
	 const char *arp_ar_sip = (char *) data;

	 return (((arp_ar_op == 2) && 0 == mmt_mem_cmp(arp_ar_sip , arp_ar_sip_1)) && 0 != mmt_mem_cmp(arp_ar_sha , arp_ar_sha_1));
 }
 
 /** 415
  * States of FSM for rule 2
  */
 
 /** 416
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_2_0, s_2_1, s_2_2, s_2_3, s_2_4;
 /** 429
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 435
  * initial state
  */
  s_2_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,
	 .description  = "IPv4 address conflict detection (RFC5227). Possible arp poisoning.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .transitions  = (fsm_transition_t[]){
		 /** 463 An arp reply with MAC address */
		 /** 465 A real event */
		 { .event_type = 1, .guard = &g_2_1, .action = 1, .target_state = &s_2_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 435
  * timeout/error state
  */
  s_2_1 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 435
  * pass state
  */
  s_2_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 435
  * inconclusive state
  */
  s_2_3 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .transitions  = NULL,
	 .transitions_count = 0
 },
 /** 435
  * root node
  */
  s_2_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 300000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  = "IPv4 address conflict detection (RFC5227). Possible arp poisoning.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .transitions  = (fsm_transition_t[]){
		 /** 465 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_2_1}, //FSM_ACTION_DO_NOTHING
		 /** 463 An arp reply but with different MAC address */
		 /** 465 A real event */
		 { .event_type = 2, .guard = &g_2_2, .action = 2, .target_state = &s_2_2}  //FSM_ACTION_RESET_TIMER
	 },
	 .transitions_count = 2
 };
 /** 492
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_2(){
		 return fsm_init( &s_2_0, &s_2_1, &s_2_2, &s_2_3, EVENTS_COUNT_2, sizeof( _msg_t_2 ) );//init, error, final, inconclusive, events_count
 }//end function
 /** 579
  * Moment the rules being encoded
  * PUBLIC API
  */
 
static const rule_version_info_t version = {.created_date=1492101710, .hash = "8eeb2e7", .number="1.6.7.0", .index=1060700, .dpi="1.6.7.0-light (ef1364e)"};
const rule_version_info_t * mmt_sec_get_rule_version_info(){ return &version;};

 //======================================GENERAL======================================
 /** 589
  * Information of 2 rules
  * PUBLIC API
  */
 size_t mmt_sec_get_plugin_info( const rule_info_t **rules_arr ){
	  static const rule_info_t rules[] = (rule_info_t[]){
		 {
			 .id               = 1,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_1,
			 .description      = "IPv4 address conflict detection (RFC5227). Possible arp poisoning.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .proto_atts_count = PROTO_ATTS_COUNT_1,
			 .proto_atts       = proto_atts_1,
			 .proto_atts_events= proto_atts_events_1,
			 .create_instance  = &create_new_fsm_1,
			 .hash_message     = &_allocate_msg_t_1,
			 .version          = &version,
		 },
		 {
			 .id               = 2,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_2,
			 .description      = "IPv4 address conflict detection (RFC5227). Possible arp poisoning.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .proto_atts_count = PROTO_ATTS_COUNT_2,
			 .proto_atts       = proto_atts_2,
			 .proto_atts_events= proto_atts_events_2,
			 .create_instance  = &create_new_fsm_2,
			 .hash_message     = &_allocate_msg_t_2,
			 .version          = &version,
		 }
	 };
	 *rules_arr = rules;
	 return 2;
 }