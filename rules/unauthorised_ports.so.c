
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
 

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/**
 * Check whether a port is unauthorised
 * - return : 1 if the port is unauthorised
 *            0 if the port is authorised
 * according to: 
 *    https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
 * and
 *    https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt
 */
static inline int check_port(int i){
  switch( i ) {
    case 78:
    case 79:
    case 100:
    case 106:
    case 787:
    case 1053:
    case 1491:
    case 2662:
    case 3060:
    case 3131:
    case 3145:
    case 3300:
    case 3301:
    case 4045:
    case 4315:
    case 4443:
    case 4967:
    case 5151:
    case 5152:
    case 5162:
    case 5444:
    case 5555:
    case 5556:
    case 6100:
    case 6200:
    case 6501:
    case 8882:
    case 9001:
    case 6632:
    case 7001:
    case 7002:
    case 7005:
    case 7011:
    case 7012:
    case 7501:
    case 7777:
    case 8001:
    case 16000:
    case 49151:
      return 1;
    default:
      if(i<1023) return 0;
		if(i>49151 && i< 65536) return 0;
		if(i>65535) return 1;
		
		if(i>2193 && i<2197) return 1;
		if(i>4488 && i<4500) return 1;
		if(i>4953 && i<4969) return 1;
		if(i>5569 && i<5573) return 1;
		if(i>5646 && i<5670) return 1;
		if(i>6657 && i<6665) return 1;
		if(i>7491 && i<7500) return 1;
		if(i>7784 && i<7790) return 1;
		if(i>27999 && i<28119) return 1;
		if(i>5554 && i<5558) return 1;
		if(i>5999 && i<6064) return 1;
		if(i>8615 && i<8665) return 1;
		if(i>8801 && i<8804) return 1;
		if(i>8887 && i<8891) return 1;
		if(i>11430 && i<11489) return 1;
		if(i>11623 && i<11720) return 1;
		if(i>27009 && i<27345) return 1;
		if(i>41797 && i<42508) return 1;
		if(i>44444 && i<44544) return 1;
  }
  return 0;
}





 //======================================RULE 3======================================
 #define EVENTS_COUNT_3 2

 #define PROTO_ATTS_COUNT_3 3

 /** 779
  * Proto_atts for rule 3
  */
 
 static proto_attribute_t proto_atts_3[ PROTO_ATTS_COUNT_3 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1, .dpi_type = 8},
 {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1, .dpi_type = 8},
 {.proto = "tcp", .proto_id = 354, .att = "dest_port", .att_id = 2, .data_type = 0, .dpi_type = 2}};
 /** 791
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_3[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 1,
		 .data = (void* []) { &proto_atts_3[ 2 ] }
	 },
	 {//event_2
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_3[ 0 ] ,  &proto_atts_3[ 1 ] }
	 } 
 };//end proto_atts_events_

 /** 522
  * Structure to represent event data
  */
 typedef struct _msg_struct_3{
	 uint16_t _ip__dst;
	 uint16_t _ip__src;
	 uint16_t _tcp__dest_port;
 }_msg_t_3;
 /** 556
  * Create an instance of _msg_t_3
  */
 static _msg_t_3 _m_index_3;
 static void _allocate_msg_t_3( const char* proto, const char* att, uint16_t index ){
	 if( strcmp( proto, "ip" ) == 0 && strcmp( att, "dst" ) == 0 ){ _m_index_3._ip__dst = index; return; }
	 if( strcmp( proto, "ip" ) == 0 && strcmp( att, "src" ) == 0 ){ _m_index_3._ip__src = index; return; }
	 if( strcmp( proto, "tcp" ) == 0 && strcmp( att, "dest_port" ) == 0 ){ _m_index_3._tcp__dest_port = index; return; }
 }
 /** 97
  * Rule 3, event 1
  * TCP packet with non-authorized port number.
  */
 static inline int g_3_1( const message_t *msg, const fsm_t *fsm ){
	 if( unlikely( msg == NULL || fsm == NULL )) return 0;
	 const message_t *his_msg;
	 const void *data;/* 63 */

	 data = get_element_data_message_t( msg, _m_index_3._tcp__dest_port );
	 if( unlikely( data == NULL )) return 0;
	 double tcp_dest_port = *(double*)  data;

	 return (check_port(tcp_dest_port) == 1);
 }
 
 /** 97
  * Rule 3, event 2
  * Print out src and dst of IP
  */
 static inline int g_3_2( const message_t *msg, const fsm_t *fsm ){
	 if( unlikely( msg == NULL || fsm == NULL )) return 0;
	 const message_t *his_msg;
	 const void *data;/* 63 */

	 data = get_element_data_message_t( msg, _m_index_3._ip__dst );
	 if( unlikely( data == NULL )) return 0;
	 const char *ip_dst = (char *) data;/* 63 */

	 data = get_element_data_message_t( msg, _m_index_3._ip__src );
	 if( unlikely( data == NULL )) return 0;
	 const char *ip_src = (char *) data;

	 return 0 != mmt_mem_cmp(ip_src , ip_dst);
 }
 
 /** 415
  * States of FSM for rule 3
  */
 
 /** 416
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_3_0, s_3_1, s_3_2, s_3_3, s_3_4;
 /** 429
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 435
  * initial state
  */
  s_3_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,
	 .description  = "C4_Analyse_3: Unauthorized port number.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .transitions  = (fsm_transition_t[]){
		 /** 463 TCP packet with non-authorized port number. */
		 /** 465 A real event */
		 { .event_type = 1, .guard = &g_3_1, .action = 1, .target_state = &s_3_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 435
  * timeout/error state
  */
  s_3_1 = {
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
  s_3_2 = {
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
  s_3_3 = {
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
  s_3_4 = {
	 .delay        = {.time_min = 0LL, .time_max = 0LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 1,
	 .description  = "C4_Analyse_3: Unauthorized port number.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .transitions  = (fsm_transition_t[]){
		 /** 465 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_3_1}, //FSM_ACTION_DO_NOTHING
		 /** 463 Print out src and dst of IP */
		 /** 465 A real event */
		 { .event_type = 2, .guard = &g_3_2, .action = 2, .target_state = &s_3_2}  //FSM_ACTION_RESET_TIMER
	 },
	 .transitions_count = 2
 };
 /** 492
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_3(){
		 return fsm_init( &s_3_0, &s_3_1, &s_3_2, &s_3_3, EVENTS_COUNT_3, sizeof( _msg_t_3 ) );//init, error, final, inconclusive, events_count
 }//end function
 /** 579
  * Moment the rules being encoded
  * PUBLIC API
  */
 
static const rule_version_info_t version = {.created_date=1492101710, .hash = "8eeb2e7", .number="1.6.7.0", .index=1060700, .dpi="1.6.7.0-light (ef1364e)"};
const rule_version_info_t * mmt_sec_get_rule_version_info(){ return &version;};

 //======================================GENERAL======================================
 /** 589
  * Information of 1 rules
  * PUBLIC API
  */
 size_t mmt_sec_get_plugin_info( const rule_info_t **rules_arr ){
	  static const rule_info_t rules[] = (rule_info_t[]){
		 {
			 .id               = 3,
			 .type_id          = 2,
			 .type_string      = "evasion",
			 .events_count     = EVENTS_COUNT_3,
			 .description      = "C4_Analyse_3: Unauthorized port number.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .proto_atts_count = PROTO_ATTS_COUNT_3,
			 .proto_atts       = proto_atts_3,
			 .proto_atts_events= proto_atts_events_3,
			 .create_instance  = &create_new_fsm_3,
			 .hash_message     = &_allocate_msg_t_3,
			 .version          = &version,
		 }
	 };
	 *rules_arr = rules;
	 return 1;
 }