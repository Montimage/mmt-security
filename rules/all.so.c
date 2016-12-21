
 /** 925
  * This file is generated automatically on 2016-12-21 18:13:11
  */
 #include <string.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include "plugin_header.h"
 #include "mmt_fsm.h"
 #include "mmt_lib.h"
 
 /** 932
  * Embedded functions
  */
 
//each function name should be prefixed by em_

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "types_defs.h"

static inline int check_ip_options(const char *op2, const char *op1){
  int handle = 0;
  
  int i2 = *((int*)op2);
  int i1 = *((int*)op1);
  int bit2 = (i2 >> 1) & 1;
  int bit1 = (i1 >> 1) & 1;
//  if(bit2 == 1 || bit1 == 1){
      if(i2 != i1) handle = 1;
//  }
  return handle;
}


static inline int check_port(int i){
  
  //printf("Port:%d\n", i);
  //according to: 
  //https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
  //and
  //https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt

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
  switch (i) {
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
      return 0;
  }
  return 0;
}

/**
* Return:
* - 0: ok
* - 1: invalid
* - 2: NULL
*/
static inline int check_URI(const char *uri_str){
  int handle = 0;
  if(uri_str == NULL){
    return 2;
  }
 
  const char *x = uri_str;
  
  //fprintf(stderr, "%s\n",x);
  while (*x != '\0'){
      //octets 0-32 (0-20 hex) | "\" | """ | "&" | "<" | ">" | "[" | "]" | "^" | "`" | "{" | "|" | "}" | "~" | octets 127-255 (7F-FF hex)
      if(*x < 32 || *x == 92 || *x == '"' || *x == '<' || *x == '>' || *x == '[' || *x == ']' || *x == '^' || *x == '`' || *x == '{' || 
         *x == '|' || *x == '}' || *x == '%' || *x > 126) {
              handle = 1;
              break;
      }
      x = x+1;
  }
  //detect directory traversal attack
  char *s0, *s1, *s2, *s3;
  s0 = strstr(uri_str, ".."); //find the first occurrence of string ".." in string
  s1 = strstr(uri_str, "./"); //find the first occurrence of string "./" in string
  s2 = strstr(uri_str, "//"); //find the first occurrence of string "//" in string
  s3 = strstr(uri_str, "/."); //find the first occurrence of string "//" in string
  
  if ((s0 !=NULL) || (s1 !=NULL) || (s2 !=NULL) || (s3 !=NULL))  
   handle = 1;
   
//#ifdef DEBUG
//  fprintf(stderr, "executing ceck_URI with parameters:h=%d:nb=%u:a1=%o:a2=%o\n", 
//                                           handle, *(char*)(BLOC3+6),*(char*)(BLOC3+9));
//#endif
  return handle;
}

/*
 * Nikto 
 */
static inline bool check_UA( const char *user_agent){
   //find the first occurrence of string "Nikto" in string
   return (strstr(user_agent, "Nikto") != NULL);     
}

static inline int check_sql_injection(const char *str, double pl){
   return 0;
   int handle = 0;
   return 0;
 
   //Signature based dection begin here. 
   //(using  pattern matching techniques against signatures and 
   //keyword-based stores to identify potentially malicious requests)

   char *s1, *s2, *s3, *s4, *s5, *s6;
   s1 = strstr(str, "DROP");  //find the first occurrence of string "DROP" in string
   s2 = strstr(str, "UNION"); //find the first occurrence of string "UNION" in string
   s3 = strstr(str, "SELECT"); //find the first occurrence of string "SELECT" in string
   s4 = strstr(str, "CHAR"); //find the first occurrence of string "CHAR" in string  
   s5 = strstr(str, "DELETE"); //find the first occurrence of string "CHAR" in string
   s6 = strstr(str, "INSERT"); //find the first occurrence of string "CHAR" in string
     
   if ((s1 !=NULL)  || (s2 !=NULL)   || (s3 !=NULL) || (s4 !=NULL) || (s5 !=NULL) || (s6 !=NULL))  {
      //printf ("SQL injection detected\n");
      handle = 1;   
   }

  return handle;
 
}



 //======================================RULE 1======================================
 #define EVENTS_COUNT_1 4

 #define PROTO_ATTS_COUNT_1 5

 /** 865
  * Proto_atts for rule 1
  */
 
 static proto_attribute_t proto_atts_1[ PROTO_ATTS_COUNT_1 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "dest_port", .att_id = 2, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "flags", .att_id = 6, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "src_port", .att_id = 1, .data_type = 0}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_1[ 5 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_1[ 0 ] ,  &proto_atts_1[ 1 ] ,  &proto_atts_1[ 2 ] ,  &proto_atts_1[ 3 ] }
	 },
	 {//event_2
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_1[ 0 ] ,  &proto_atts_1[ 1 ] ,  &proto_atts_1[ 3 ] ,  &proto_atts_1[ 4 ] }
	 },
	 {//event_3
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_1[ 0 ] ,  &proto_atts_1[ 1 ] ,  &proto_atts_1[ 2 ] ,  &proto_atts_1[ 3 ] }
	 },
	 {//event_4
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_1[ 0 ] ,  &proto_atts_1[ 1 ] ,  &proto_atts_1[ 3 ] ,  &proto_atts_1[ 4 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_1{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const char *ip_src;
	 const double *tcp_dest_port;
	 const double *tcp_flags;
	 const double *tcp_src_port;
 }_msg_t_1;
 /** 592
  * Create an instance of _msg_t_1
  */
 static inline _msg_t_1* _allocate_msg_t_1(){
	 _msg_t_1 *m = mmt_mem_alloc( sizeof( _msg_t_1 ));
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
 static void *convert_message_to_event_1( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_1 *new_msg = _allocate_msg_t_1();
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
 static const uint16_t* hash_message_1( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_1 ];
	 size_t i;	 _msg_t_1 *msg = (_msg_t_1 *) data;
	 for( i=0; i<EVENTS_COUNT_1; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_dest_port != NULL && msg->tcp_flags != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_flags != NULL && msg->tcp_src_port != NULL )
		 hash_table[ 1 ] = 2;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_dest_port != NULL && msg->tcp_flags != NULL )
		 hash_table[ 2 ] = 3;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_flags != NULL && msg->tcp_src_port != NULL )
		 hash_table[ 3 ] = 4;
	 return hash_table;
 }
 /** 94
  * Rule 1, event 1
  * SYN request
  */
 static inline int g_1_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_1 *his_data, *ev_data = (_msg_t_1 *) event_data;/* 61 */
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
  * Rule 1, event 2
  * SYN ACK reply
  */
 static inline int g_1_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_1 *his_data, *ev_data = (_msg_t_1 *) event_data;
	 his_data = (_msg_t_1 *)fsm_get_history( fsm, 1);
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
  * Rule 1, event 3
  * SYN request
  */
 static inline int g_1_3( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_1 *his_data, *ev_data = (_msg_t_1 *) event_data;
	 his_data = (_msg_t_1 *)fsm_get_history( fsm, 1);
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

	 return ((tcp_flags == 2) && ((tcp_dest_port == 22) && (0 == strcmp(ip_src , ip_src_1) && 0 == strcmp(ip_dst , ip_dst_1))));
 }
 
 /** 94
  * Rule 1, event 4
  * SYN ACK reply
  */
 static inline int g_1_4( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_1 *his_data, *ev_data = (_msg_t_1 *) event_data;
	 his_data = (_msg_t_1 *)fsm_get_history( fsm, 1);
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
 
 /** 407
  * States of FSM for rule 1
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_1_0, s_1_1, s_1_2, s_1_3, s_1_4, s_1_5, s_1_6;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_1_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "Several attempts to connect via ssh (brute force attack). Source address is either infected machine or attacker (no spoofing is possible).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 SYN request */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_1_1, .action = 1, .target_state = &s_1_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
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
 /** 427
  * final state
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
 }, s_1_3 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_1_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 1000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_1_3}, //FSM_ACTION_DO_NOTHING
		 /** 456 SYN ACK reply */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_1_2, .action = 1, .target_state = &s_1_5}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 2
 },
 /** 427
  * root node
  */
  s_1_5 = {
	 .delay        = {.time_min = 1LL, .time_max = 60000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  = "Several attempts to connect via ssh (brute force attack). Source address is either infected machine or attacker (no spoofing is possible).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_1_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 SYN request */
		 /** 458 A real event */
		 { .event_type = 3, .guard = &g_1_3, .action = 1, .target_state = &s_1_6}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 2
 }, s_1_6 = {
	 .delay        = {.time_min = 1LL, .time_max = 1000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_1_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 SYN ACK reply */
		 /** 458 A real event */
		 { .event_type = 4, .guard = &g_1_4, .action = 0, .target_state = &s_1_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_1(){
		 return fsm_init( &s_1_0, &s_1_1, &s_1_2, &s_1_3, EVENTS_COUNT_1 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 2======================================
 #define EVENTS_COUNT_2 3

 #define PROTO_ATTS_COUNT_2 5

 /** 865
  * Proto_atts for rule 2
  */
 
 static proto_attribute_t proto_atts_2[ PROTO_ATTS_COUNT_2 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "dest_port", .att_id = 2, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "flags", .att_id = 6, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "src_port", .att_id = 1, .data_type = 0}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_2[ 4 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_2[ 0 ] ,  &proto_atts_2[ 1 ] ,  &proto_atts_2[ 2 ] ,  &proto_atts_2[ 3 ] }
	 },
	 {//event_2
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_2[ 0 ] ,  &proto_atts_2[ 1 ] ,  &proto_atts_2[ 3 ] ,  &proto_atts_2[ 4 ] }
	 },
	 {//event_3
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_2[ 0 ] ,  &proto_atts_2[ 1 ] ,  &proto_atts_2[ 2 ] ,  &proto_atts_2[ 3 ] }
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

 //======================================RULE 3======================================
 #define EVENTS_COUNT_3 2

 #define PROTO_ATTS_COUNT_3 4

 /** 865
  * Proto_atts for rule 3
  */
 
 static proto_attribute_t proto_atts_3[ PROTO_ATTS_COUNT_3 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "dest_port", .att_id = 2, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "flags", .att_id = 6, .data_type = 0}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_3[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_3[ 0 ] ,  &proto_atts_3[ 1 ] ,  &proto_atts_3[ 2 ] ,  &proto_atts_3[ 3 ] }
	 },
	 {//event_2
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_3[ 1 ] ,  &proto_atts_3[ 3 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_3{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const char *ip_src;
	 const double *tcp_dest_port;
	 const double *tcp_flags;
 }_msg_t_3;
 /** 592
  * Create an instance of _msg_t_3
  */
 static inline _msg_t_3* _allocate_msg_t_3(){
	 _msg_t_3 *m = mmt_mem_alloc( sizeof( _msg_t_3 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_dest_port = NULL;
	 m->tcp_flags = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_3( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_3 *new_msg = _allocate_msg_t_3();
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
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_3( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_3 ];
	 size_t i;	 _msg_t_3 *msg = (_msg_t_3 *) data;
	 for( i=0; i<EVENTS_COUNT_3; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_dest_port != NULL && msg->tcp_flags != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_src != NULL && msg->tcp_flags != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 3, event 1
  * SYN request
  */
 static inline int g_3_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_3 *his_data, *ev_data = (_msg_t_3 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->tcp_dest_port == NULL )) return 0;
	 double tcp_dest_port = *( ev_data->tcp_dest_port );/* 61 */
	 if( unlikely( ev_data->tcp_flags == NULL )) return 0;
	 double tcp_flags = *( ev_data->tcp_flags );

	 return ((tcp_flags == 2) && ((tcp_dest_port == 445) && 0 != strcmp(ip_src , ip_dst)));
 }
 
 /** 94
  * Rule 3, event 2
  * SYN ACK reply
  */
 static inline int g_3_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_3 *his_data, *ev_data = (_msg_t_3 *) event_data;
	 his_data = (_msg_t_3 *)fsm_get_history( fsm, 1);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_dst == NULL )) return 0;
	 const char *ip_dst_1 =  his_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->tcp_flags == NULL )) return 0;
	 double tcp_flags = *( ev_data->tcp_flags );

	 return ((tcp_flags == 18) && 0 == strcmp(ip_src , ip_dst_1));
 }
 
 /** 407
  * States of FSM for rule 3
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_3_0, s_3_1, s_3_2, s_3_3, s_3_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_3_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "TCP SYN requests on microsoft-ds port 445 with SYN ACK.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 SYN request */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_3_1, .action = 1, .target_state = &s_3_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_3_1 = {
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
  s_3_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_3_3 = {
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
  * root node
  */
  s_3_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 6000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  = "TCP SYN requests on microsoft-ds port 445 with SYN ACK.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_3_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 SYN ACK reply */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_3_2, .action = 0, .target_state = &s_3_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_3(){
		 return fsm_init( &s_3_0, &s_3_1, &s_3_2, &s_3_3, EVENTS_COUNT_3 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 6======================================
 #define EVENTS_COUNT_6 2

 #define PROTO_ATTS_COUNT_6 5

 /** 865
  * Proto_atts for rule 6
  */
 
 static proto_attribute_t proto_atts_6[ PROTO_ATTS_COUNT_6 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "ack_nb", .att_id = 4, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "flags", .att_id = 6, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "seq_nb", .att_id = 3, .data_type = 0}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_6[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_6[ 0 ] ,  &proto_atts_6[ 1 ] ,  &proto_atts_6[ 3 ] ,  &proto_atts_6[ 4 ] }
	 },
	 {//event_2
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_6[ 0 ] ,  &proto_atts_6[ 1 ] ,  &proto_atts_6[ 2 ] ,  &proto_atts_6[ 3 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_6{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const char *ip_src;
	 const double *tcp_ack_nb;
	 const double *tcp_flags;
	 const double *tcp_seq_nb;
 }_msg_t_6;
 /** 592
  * Create an instance of _msg_t_6
  */
 static inline _msg_t_6* _allocate_msg_t_6(){
	 _msg_t_6 *m = mmt_mem_alloc( sizeof( _msg_t_6 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_ack_nb = NULL;
	 m->tcp_flags = NULL;
	 m->tcp_seq_nb = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_6( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_6 *new_msg = _allocate_msg_t_6();
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
			 case 4:// attribute ack_nb
				 new_msg->tcp_ack_nb = (double *) msg->elements[i].data;
				 break;
			 case 6:// attribute flags
				 new_msg->tcp_flags = (double *) msg->elements[i].data;
				 break;
			 case 3:// attribute seq_nb
				 new_msg->tcp_seq_nb = (double *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_6( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_6 ];
	 size_t i;	 _msg_t_6 *msg = (_msg_t_6 *) data;
	 for( i=0; i<EVENTS_COUNT_6; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_flags != NULL && msg->tcp_seq_nb != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_ack_nb != NULL && msg->tcp_flags != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 6, event 1
  * TCP SYN
  */
 static inline int g_6_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_6 *his_data, *ev_data = (_msg_t_6 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->tcp_flags == NULL )) return 0;
	 double tcp_flags = *( ev_data->tcp_flags );/* 61 */
	 if( unlikely( ev_data->tcp_seq_nb == NULL )) return 0;
	 double tcp_seq_nb = *( ev_data->tcp_seq_nb );

	 return ((tcp_flags == 2) && (0 == strcmp(ip_dst , ip_dst) && (0 == strcmp(ip_src , ip_src) && (tcp_seq_nb == tcp_seq_nb))));
 }
 
 /** 94
  * Rule 6, event 2
  * TCP ACK
  */
 static inline int g_6_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_6 *his_data, *ev_data = (_msg_t_6 *) event_data;
	 his_data = (_msg_t_6 *)fsm_get_history( fsm, 1);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_dst == NULL )) return 0;
	 const char *ip_dst_1 =  his_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( his_data->ip_src == NULL )) return 0;
	 const char *ip_src_1 =  his_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->tcp_ack_nb == NULL )) return 0;
	 double tcp_ack_nb = *( ev_data->tcp_ack_nb );/* 61 */
	 if( unlikely( ev_data->tcp_flags == NULL )) return 0;
	 double tcp_flags = *( ev_data->tcp_flags );/* 61 */
	 if( unlikely( his_data->tcp_seq_nb == NULL )) return 0;
	 double tcp_seq_nb_1 = *( his_data->tcp_seq_nb );

	 return ((tcp_flags == 16) && (0 == strcmp(ip_dst , ip_src_1) && (0 == strcmp(ip_src , ip_dst_1) && (((tcp_ack_nb - tcp_seq_nb_1) == 791101) || ((tcp_seq_nb_1 - tcp_ack_nb) == 791101)))));
 }
 
 /** 407
  * States of FSM for rule 6
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_6_0, s_6_1, s_6_2, s_6_3, s_6_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_6_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "4_Analyse_03b : SYN and ACK paquets with a 0xC123D delta between TCP sequence numbers (scan done by SYNFUL attack).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 TCP SYN */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_6_1, .action = 1, .target_state = &s_6_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_6_1 = {
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
  s_6_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_6_3 = {
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
  * root node
  */
  s_6_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 1000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  = "4_Analyse_03b : SYN and ACK paquets with a 0xC123D delta between TCP sequence numbers (scan done by SYNFUL attack).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_6_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 TCP ACK */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_6_2, .action = 0, .target_state = &s_6_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_6(){
		 return fsm_init( &s_6_0, &s_6_1, &s_6_2, &s_6_3, EVENTS_COUNT_6 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 7======================================
 #define EVENTS_COUNT_7 2

 #define PROTO_ATTS_COUNT_7 6

 /** 865
  * Proto_atts for rule 7
  */
 
 static proto_attribute_t proto_atts_7[ PROTO_ATTS_COUNT_7 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "ack_nb", .att_id = 4, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "flags", .att_id = 6, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "rst", .att_id = 9, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "seq_nb", .att_id = 3, .data_type = 0}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_7[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_7[ 0 ] ,  &proto_atts_7[ 1 ] ,  &proto_atts_7[ 4 ] ,  &proto_atts_7[ 5 ] }
	 },
	 {//event_2
		 .elements_count = 5,
		 .data = (void* []) { &proto_atts_7[ 0 ] ,  &proto_atts_7[ 1 ] ,  &proto_atts_7[ 2 ] ,  &proto_atts_7[ 3 ] ,  &proto_atts_7[ 5 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_7{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const char *ip_src;
	 const double *tcp_ack_nb;
	 const double *tcp_flags;
	 const double *tcp_rst;
	 const double *tcp_seq_nb;
 }_msg_t_7;
 /** 592
  * Create an instance of _msg_t_7
  */
 static inline _msg_t_7* _allocate_msg_t_7(){
	 _msg_t_7 *m = mmt_mem_alloc( sizeof( _msg_t_7 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_ack_nb = NULL;
	 m->tcp_flags = NULL;
	 m->tcp_rst = NULL;
	 m->tcp_seq_nb = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_7( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_7 *new_msg = _allocate_msg_t_7();
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
			 case 4:// attribute ack_nb
				 new_msg->tcp_ack_nb = (double *) msg->elements[i].data;
				 break;
			 case 6:// attribute flags
				 new_msg->tcp_flags = (double *) msg->elements[i].data;
				 break;
			 case 9:// attribute rst
				 new_msg->tcp_rst = (double *) msg->elements[i].data;
				 break;
			 case 3:// attribute seq_nb
				 new_msg->tcp_seq_nb = (double *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_7( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_7 ];
	 size_t i;	 _msg_t_7 *msg = (_msg_t_7 *) data;
	 for( i=0; i<EVENTS_COUNT_7; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_rst != NULL && msg->tcp_seq_nb != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_ack_nb != NULL && msg->tcp_flags != NULL && msg->tcp_seq_nb != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 7, event 1
  * Context: TCP RST
  */
 static inline int g_7_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_7 *his_data, *ev_data = (_msg_t_7 *) event_data;
	 his_data = (_msg_t_7 *)fsm_get_history( fsm, 2);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_dst == NULL )) return 0;
	 const char *ip_dst_2 =  his_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( his_data->ip_src == NULL )) return 0;
	 const char *ip_src_2 =  his_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;/* 61 */
	 if( unlikely( his_data->tcp_ack_nb == NULL )) return 0;
	 double tcp_ack_nb_2 = *( his_data->tcp_ack_nb );/* 61 */
	 if( unlikely( ev_data->tcp_rst == NULL )) return 0;
	 double tcp_rst = *( ev_data->tcp_rst );/* 61 */
	 if( unlikely( ev_data->tcp_seq_nb == NULL )) return 0;
	 double tcp_seq_nb = *( ev_data->tcp_seq_nb );

	 return ((tcp_rst == 1) && ((tcp_ack_nb_2 != tcp_seq_nb) && (0 == strcmp(ip_src_2 , ip_dst) && 0 == strcmp(ip_dst_2 , ip_src))));
 }
 
 /** 94
  * Rule 7, event 2
  * Trigger: the last TCP ACK packets have different seg_nb and ack_nb
  */
 static inline int g_7_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_7 *his_data, *ev_data = (_msg_t_7 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->tcp_flags == NULL )) return 0;
	 double tcp_flags = *( ev_data->tcp_flags );/* 61 */
	 if( unlikely( ev_data->tcp_seq_nb == NULL )) return 0;
	 double tcp_seq_nb = *( ev_data->tcp_seq_nb );

	 return ((tcp_flags == 16) && ((tcp_seq_nb == tcp_seq_nb) && 0 != strcmp(ip_src , ip_dst)));
 }
 
 /** 407
  * States of FSM for rule 7
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_7_0, s_7_1, s_7_2, s_7_3, s_7_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_7_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "R4_Decod_1a : TCP RST is invalid if there is no corresponding TCP ACK (tcp.flags == 16) before belonging to the same session containing correct seq_nb and ack_nb.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 Context: TCP RST */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_7_1, .action = 1, .target_state = &s_7_1}, //FSM_ACTION_CREATE_INSTANCE
		 /** 456 Trigger: the last TCP ACK packets have different seg_nb and ack_nb */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_7_2, .action = 1, .target_state = &s_7_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 2
 },
 /** 427
  * timeout/error state
  */
  s_7_1 = {
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
  s_7_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_7_3 = {
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
  * root node
  */
  s_7_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 1000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  = "R4_Decod_1a : TCP RST is invalid if there is no corresponding TCP ACK (tcp.flags == 16) before belonging to the same session containing correct seq_nb and ack_nb.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_7_3}, //FSM_ACTION_DO_NOTHING
		 /** 456 Context: TCP RST */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_7_1, .action = 0, .target_state = &s_7_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_7(){
		 return fsm_init( &s_7_0, &s_7_1, &s_7_2, &s_7_3, EVENTS_COUNT_7 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 8======================================
 #define EVENTS_COUNT_8 2

 #define PROTO_ATTS_COUNT_8 4

 /** 865
  * Proto_atts for rule 8
  */
 
 static proto_attribute_t proto_atts_8[ PROTO_ATTS_COUNT_8 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "mf_flag", .att_id = 7, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "options", .att_id = 14, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_8[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_8[ 0 ] ,  &proto_atts_8[ 1 ] ,  &proto_atts_8[ 2 ] ,  &proto_atts_8[ 3 ] }
	 },
	 {//event_2
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_8[ 0 ] ,  &proto_atts_8[ 1 ] ,  &proto_atts_8[ 2 ] ,  &proto_atts_8[ 3 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_8{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const double *ip_mf_flag;
	 const char *ip_options;
	 const char *ip_src;
 }_msg_t_8;
 /** 592
  * Create an instance of _msg_t_8
  */
 static inline _msg_t_8* _allocate_msg_t_8(){
	 _msg_t_8 *m = mmt_mem_alloc( sizeof( _msg_t_8 ));
	 m->ip_dst = NULL;
	 m->ip_mf_flag = NULL;
	 m->ip_options = NULL;
	 m->ip_src = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_8( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_8 *new_msg = _allocate_msg_t_8();
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
			 case 7:// attribute mf_flag
				 new_msg->ip_mf_flag = (double *) msg->elements[i].data;
				 break;
			 case 14:// attribute options
				 new_msg->ip_options = (char *) msg->elements[i].data;
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_8( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_8 ];
	 size_t i;	 _msg_t_8 *msg = (_msg_t_8 *) data;
	 for( i=0; i<EVENTS_COUNT_8; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->ip_dst != NULL && msg->ip_mf_flag != NULL && msg->ip_options != NULL && msg->ip_src != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_mf_flag != NULL && msg->ip_options != NULL && msg->ip_src != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 8, event 1
  * IP segment
  */
 static inline int g_8_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_8 *his_data, *ev_data = (_msg_t_8 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_mf_flag == NULL )) return 0;
	 double ip_mf_flag = *( ev_data->ip_mf_flag );/* 61 */
	 if( unlikely( ev_data->ip_options == NULL )) return 0;
	 const char *ip_options =  ev_data->ip_options ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return ((ip_mf_flag > 0) && (0 == strcmp(ip_options , ip_options) && 0 != strcmp(ip_src , ip_dst)));
 }
 
 /** 94
  * Rule 8, event 2
  * IP options
  */
 static inline int g_8_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_8 *his_data, *ev_data = (_msg_t_8 *) event_data;
	 his_data = (_msg_t_8 *)fsm_get_history( fsm, 1);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_dst == NULL )) return 0;
	 const char *ip_dst_1 =  his_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_mf_flag == NULL )) return 0;
	 double ip_mf_flag = *( ev_data->ip_mf_flag );/* 61 */
	 if( unlikely( his_data->ip_options == NULL )) return 0;
	 const char *ip_options_1 =  his_data->ip_options ;/* 61 */
	 if( unlikely( ev_data->ip_options == NULL )) return 0;
	 const char *ip_options =  ev_data->ip_options ;/* 61 */
	 if( unlikely( his_data->ip_src == NULL )) return 0;
	 const char *ip_src_1 =  his_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return ((ip_mf_flag > 0) && (0 == strcmp(ip_src , ip_src_1) && (0 == strcmp(ip_dst , ip_dst_1) && (check_ip_options(ip_options , ip_options_1) == 1))));
 }
 
 /** 407
  * States of FSM for rule 8
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_8_0, s_8_1, s_8_2, s_8_3, s_8_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_8_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "C4_Analyse_03g: The IP options field must be homogeneous in all IP fragments.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 IP segment */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_8_1, .action = 1, .target_state = &s_8_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_8_1 = {
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
  s_8_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_8_3 = {
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
  * root node
  */
  s_8_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 1000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  = "C4_Analyse_03g: The IP options field must be homogeneous in all IP fragments.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_8_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 IP options */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_8_2, .action = 0, .target_state = &s_8_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_8(){
		 return fsm_init( &s_8_0, &s_8_1, &s_8_2, &s_8_3, EVENTS_COUNT_8 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 9======================================
 #define EVENTS_COUNT_9 2

 #define PROTO_ATTS_COUNT_9 5

 /** 865
  * Proto_atts for rule 9
  */
 
 static proto_attribute_t proto_atts_9[ PROTO_ATTS_COUNT_9 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "frag_offset", .att_id = 8, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "mf_flag", .att_id = 7, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "tot_len", .att_id = 4, .data_type = 0}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_9[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 3,
		 .data = (void* []) { &proto_atts_9[ 1 ] ,  &proto_atts_9[ 2 ] ,  &proto_atts_9[ 4 ] }
	 },
	 {//event_2
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_9[ 0 ] ,  &proto_atts_9[ 3 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_9{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const double *ip_frag_offset;
	 const double *ip_mf_flag;
	 const char *ip_src;
	 const double *ip_tot_len;
 }_msg_t_9;
 /** 592
  * Create an instance of _msg_t_9
  */
 static inline _msg_t_9* _allocate_msg_t_9(){
	 _msg_t_9 *m = mmt_mem_alloc( sizeof( _msg_t_9 ));
	 m->ip_dst = NULL;
	 m->ip_frag_offset = NULL;
	 m->ip_mf_flag = NULL;
	 m->ip_src = NULL;
	 m->ip_tot_len = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_9( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_9 *new_msg = _allocate_msg_t_9();
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
			 case 8:// attribute frag_offset
				 new_msg->ip_frag_offset = (double *) msg->elements[i].data;
				 break;
			 case 7:// attribute mf_flag
				 new_msg->ip_mf_flag = (double *) msg->elements[i].data;
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) msg->elements[i].data;
				 break;
			 case 4:// attribute tot_len
				 new_msg->ip_tot_len = (double *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_9( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_9 ];
	 size_t i;	 _msg_t_9 *msg = (_msg_t_9 *) data;
	 for( i=0; i<EVENTS_COUNT_9; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->ip_frag_offset != NULL && msg->ip_mf_flag != NULL && msg->ip_tot_len != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 9, event 1
  * IP segment and paquet size
  */
 static inline int g_9_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_9 *his_data, *ev_data = (_msg_t_9 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_frag_offset == NULL )) return 0;
	 double ip_frag_offset = *( ev_data->ip_frag_offset );/* 61 */
	 if( unlikely( ev_data->ip_mf_flag == NULL )) return 0;
	 double ip_mf_flag = *( ev_data->ip_mf_flag );/* 61 */
	 if( unlikely( ev_data->ip_tot_len == NULL )) return 0;
	 double ip_tot_len = *( ev_data->ip_tot_len );

	 return ((ip_mf_flag > 0) && ((ip_tot_len < 28) || ((ip_frag_offset == 0) && (ip_tot_len < 4))));
 }
 
 /** 94
  * Rule 9, event 2
  * IP segment
  */
 static inline int g_9_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_9 *his_data, *ev_data = (_msg_t_9 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return 0 != strcmp(ip_src , ip_dst);
 }
 
 /** 407
  * States of FSM for rule 9
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_9_0, s_9_1, s_9_2, s_9_3, s_9_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_9_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "C4_Analyse_03h: The minimum size of an IP fragment is 28 bytes and for an IP fragment with offset 0 it is 40.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 IP segment and paquet size */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_9_1, .action = 1, .target_state = &s_9_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_9_1 = {
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
  s_9_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_9_3 = {
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
  * root node
  */
  s_9_4 = {
	 .delay        = {.time_min = 0LL, .time_max = 0LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 1,
	 .description  = "C4_Analyse_03h: The minimum size of an IP fragment is 28 bytes and for an IP fragment with offset 0 it is 40.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_9_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 IP segment */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_9_2, .action = 0, .target_state = &s_9_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_9(){
		 return fsm_init( &s_9_0, &s_9_1, &s_9_2, &s_9_3, EVENTS_COUNT_9 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 10======================================
 #define EVENTS_COUNT_10 2

 #define PROTO_ATTS_COUNT_10 4

 /** 865
  * Proto_atts for rule 10
  */
 
 static proto_attribute_t proto_atts_10[ PROTO_ATTS_COUNT_10 ] = {{.proto = "http", .proto_id = 153, .att = "method", .att_id = 1, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "dest_port", .att_id = 2, .data_type = 0}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_10[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_10[ 0 ] ,  &proto_atts_10[ 3 ] }
	 },
	 {//event_2
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_10[ 1 ] ,  &proto_atts_10[ 2 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_10{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *http_method;
	 const char *ip_dst;
	 const char *ip_src;
	 const double *tcp_dest_port;
 }_msg_t_10;
 /** 592
  * Create an instance of _msg_t_10
  */
 static inline _msg_t_10* _allocate_msg_t_10(){
	 _msg_t_10 *m = mmt_mem_alloc( sizeof( _msg_t_10 ));
	 m->http_method = NULL;
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_dest_port = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_10( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_10 *new_msg = _allocate_msg_t_10();
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i].proto_id ){/** 626 For each protocol*/
		 case 153:// protocol http
			 switch( msg->elements[i].att_id ){
			 case 1:// attribute method
				 new_msg->http_method = (char *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 633
			 break;
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
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_10( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_10 ];
	 size_t i;	 _msg_t_10 *msg = (_msg_t_10 *) data;
	 for( i=0; i<EVENTS_COUNT_10; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->http_method != NULL && msg->tcp_dest_port != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 10, event 1
  * HTTP packet using a port different from 80 and 8080
  */
 static inline int g_10_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_10 *his_data, *ev_data = (_msg_t_10 *) event_data;/* 61 */
	 if( unlikely( ev_data->http_method == NULL )) return 0;
	 const char *http_method =  ev_data->http_method ;/* 61 */
	 if( unlikely( ev_data->tcp_dest_port == NULL )) return 0;
	 double tcp_dest_port = *( ev_data->tcp_dest_port );

	 return (0 == strcmp(http_method , http_method) && ((tcp_dest_port != 8) && (tcp_dest_port != 808)));
 }
 
 /** 94
  * Rule 10, event 2
  * HTTP packet
  */
 static inline int g_10_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_10 *his_data, *ev_data = (_msg_t_10 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return 0 != strcmp(ip_src , ip_dst);
 }
 
 /** 407
  * States of FSM for rule 10
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_10_0, s_10_1, s_10_2, s_10_3, s_10_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_10_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "C4_Analyse_03f : HTTP using a port different from 80 and 8080.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 HTTP packet using a port different from 80 and 8080 */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_10_1, .action = 1, .target_state = &s_10_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_10_1 = {
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
  s_10_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_10_3 = {
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
  * root node
  */
  s_10_4 = {
	 .delay        = {.time_min = 0LL, .time_max = 0LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 1,
	 .description  = "C4_Analyse_03f : HTTP using a port different from 80 and 8080.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_10_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 HTTP packet */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_10_2, .action = 0, .target_state = &s_10_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_10(){
		 return fsm_init( &s_10_0, &s_10_1, &s_10_2, &s_10_3, EVENTS_COUNT_10 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 11======================================
 #define EVENTS_COUNT_11 2

 #define PROTO_ATTS_COUNT_11 4

 /** 865
  * Proto_atts for rule 11
  */
 
 static proto_attribute_t proto_atts_11[ PROTO_ATTS_COUNT_11 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "tot_len", .att_id = 4, .data_type = 0}, {.proto = "meta", .proto_id = 1, .att = "packet_len", .att_id = 4, .data_type = 0}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_11[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_11[ 2 ] ,  &proto_atts_11[ 3 ] }
	 },
	 {//event_2
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_11[ 0 ] ,  &proto_atts_11[ 1 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_11{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const char *ip_src;
	 const double *ip_tot_len;
	 const double *meta_packet_len;
 }_msg_t_11;
 /** 592
  * Create an instance of _msg_t_11
  */
 static inline _msg_t_11* _allocate_msg_t_11(){
	 _msg_t_11 *m = mmt_mem_alloc( sizeof( _msg_t_11 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->ip_tot_len = NULL;
	 m->meta_packet_len = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_11( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_11 *new_msg = _allocate_msg_t_11();
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
			 case 4:// attribute tot_len
				 new_msg->ip_tot_len = (double *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 633
			 break;
		 case 1:// protocol meta
			 switch( msg->elements[i].att_id ){
			 case 4:// attribute packet_len
				 new_msg->meta_packet_len = (double *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_11( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_11 ];
	 size_t i;	 _msg_t_11 *msg = (_msg_t_11 *) data;
	 for( i=0; i<EVENTS_COUNT_11; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->ip_tot_len != NULL && msg->meta_packet_len != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 11, event 1
  * Paquet size
  */
 static inline int g_11_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_11 *his_data, *ev_data = (_msg_t_11 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_tot_len == NULL )) return 0;
	 double ip_tot_len = *( ev_data->ip_tot_len );/* 61 */
	 if( unlikely( ev_data->meta_packet_len == NULL )) return 0;
	 double meta_packet_len = *( ev_data->meta_packet_len );

	 return ((meta_packet_len < 34) && (ip_tot_len > 0));
 }
 
 /** 94
  * Rule 11, event 2
  * IP segment
  */
 static inline int g_11_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_11 *his_data, *ev_data = (_msg_t_11 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return 0 != strcmp(ip_src , ip_dst);
 }
 
 /** 407
  * States of FSM for rule 11
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_11_0, s_11_1, s_11_2, s_11_3, s_11_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_11_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "C4_Analyse_03h: IP packet size and eth payload size not coherent.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 Paquet size */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_11_1, .action = 1, .target_state = &s_11_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_11_1 = {
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
  s_11_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_11_3 = {
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
  * root node
  */
  s_11_4 = {
	 .delay        = {.time_min = 0LL, .time_max = 0LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 1,
	 .description  = "C4_Analyse_03h: IP packet size and eth payload size not coherent.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_11_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 IP segment */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_11_2, .action = 0, .target_state = &s_11_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_11(){
		 return fsm_init( &s_11_0, &s_11_1, &s_11_2, &s_11_3, EVENTS_COUNT_11 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 12======================================
 #define EVENTS_COUNT_12 2

 #define PROTO_ATTS_COUNT_12 4

 /** 865
  * Proto_atts for rule 12
  */
 
 static proto_attribute_t proto_atts_12[ PROTO_ATTS_COUNT_12 ] = {{.proto = "http", .proto_id = 153, .att = "method", .att_id = 1, .data_type = 1}, {.proto = "http", .proto_id = 153, .att = "uri", .att_id = 4, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_12[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_12[ 0 ] ,  &proto_atts_12[ 1 ] }
	 },
	 {//event_2
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_12[ 2 ] ,  &proto_atts_12[ 3 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_12{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *http_method;
	 const char *http_uri;
	 const char *ip_dst;
	 const char *ip_src;
 }_msg_t_12;
 /** 592
  * Create an instance of _msg_t_12
  */
 static inline _msg_t_12* _allocate_msg_t_12(){
	 _msg_t_12 *m = mmt_mem_alloc( sizeof( _msg_t_12 ));
	 m->http_method = NULL;
	 m->http_uri = NULL;
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_12( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_12 *new_msg = _allocate_msg_t_12();
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i].proto_id ){/** 626 For each protocol*/
		 case 153:// protocol http
			 switch( msg->elements[i].att_id ){
			 case 1:// attribute method
				 new_msg->http_method = (char *) msg->elements[i].data;
				 break;
			 case 4:// attribute uri
				 new_msg->http_uri = (char *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 633
			 break;
		 case 178:// protocol ip
			 switch( msg->elements[i].att_id ){
			 case 13:// attribute dst
				 new_msg->ip_dst = (char *) msg->elements[i].data;
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_12( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_12 ];
	 size_t i;	 _msg_t_12 *msg = (_msg_t_12 *) data;
	 for( i=0; i<EVENTS_COUNT_12; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->http_method != NULL && msg->http_uri != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 12, event 1
  * HTTP URI invalid
  */
 static inline int g_12_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_12 *his_data, *ev_data = (_msg_t_12 *) event_data;/* 61 */
	 if( unlikely( ev_data->http_method == NULL )) return 0;
	 const char *http_method =  ev_data->http_method ;/* 61 */
	 if( unlikely( ev_data->http_uri == NULL )) return 0;
	 const char *http_uri =  ev_data->http_uri ;

	 return (0 == strcmp(http_method , http_method) && (check_URI(http_uri) == 1));
 }
 
 /** 94
  * Rule 12, event 2
  * HTTP packet
  */
 static inline int g_12_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_12 *his_data, *ev_data = (_msg_t_12 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return 0 != strcmp(ip_src , ip_dst);
 }
 
 /** 407
  * States of FSM for rule 12
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_12_0, s_12_1, s_12_2, s_12_3, s_12_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_12_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "C4_Analyse_03c|d|e : HTTP packet URI contains non authorised characteres according to RFC2396 and RFC2234 or possibly directory traversal attack.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 HTTP URI invalid */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_12_1, .action = 1, .target_state = &s_12_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_12_1 = {
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
  s_12_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_12_3 = {
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
  * root node
  */
  s_12_4 = {
	 .delay        = {.time_min = 0LL, .time_max = 0LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 1,
	 .description  = "C4_Analyse_03c|d|e : HTTP packet URI contains non authorised characteres according to RFC2396 and RFC2234 or possibly directory traversal attack.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_12_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 HTTP packet */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_12_2, .action = 0, .target_state = &s_12_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_12(){
		 return fsm_init( &s_12_0, &s_12_1, &s_12_2, &s_12_3, EVENTS_COUNT_12 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 13======================================
 #define EVENTS_COUNT_13 2

 #define PROTO_ATTS_COUNT_13 4

 /** 865
  * Proto_atts for rule 13
  */
 
 static proto_attribute_t proto_atts_13[ PROTO_ATTS_COUNT_13 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "flags", .att_id = 6, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "payload_len", .att_id = 23, .data_type = 0}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_13[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_13[ 2 ] ,  &proto_atts_13[ 3 ] }
	 },
	 {//event_2
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_13[ 0 ] ,  &proto_atts_13[ 1 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_13{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const char *ip_src;
	 const double *tcp_flags;
	 const double *tcp_payload_len;
 }_msg_t_13;
 /** 592
  * Create an instance of _msg_t_13
  */
 static inline _msg_t_13* _allocate_msg_t_13(){
	 _msg_t_13 *m = mmt_mem_alloc( sizeof( _msg_t_13 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_flags = NULL;
	 m->tcp_payload_len = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_13( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_13 *new_msg = _allocate_msg_t_13();
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
			 case 6:// attribute flags
				 new_msg->tcp_flags = (double *) msg->elements[i].data;
				 break;
			 case 23:// attribute payload_len
				 new_msg->tcp_payload_len = (double *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_13( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_13 ];
	 size_t i;	 _msg_t_13 *msg = (_msg_t_13 *) data;
	 for( i=0; i<EVENTS_COUNT_13; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->tcp_flags != NULL && msg->tcp_payload_len != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 13, event 1
  * SYN request
  */
 static inline int g_13_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_13 *his_data, *ev_data = (_msg_t_13 *) event_data;/* 61 */
	 if( unlikely( ev_data->tcp_flags == NULL )) return 0;
	 double tcp_flags = *( ev_data->tcp_flags );/* 61 */
	 if( unlikely( ev_data->tcp_payload_len == NULL )) return 0;
	 double tcp_payload_len = *( ev_data->tcp_payload_len );

	 return ((tcp_flags == 2) && (tcp_payload_len > 0));
 }
 
 /** 94
  * Rule 13, event 2
  * SYN ACK reply
  */
 static inline int g_13_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_13 *his_data, *ev_data = (_msg_t_13 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return 0 != strcmp(ip_src , ip_dst);
 }
 
 /** 407
  * States of FSM for rule 13
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_13_0, s_13_1, s_13_2, s_13_3, s_13_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_13_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "C4_Analyse_3b : Data in SYN packet.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 SYN request */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_13_1, .action = 1, .target_state = &s_13_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_13_1 = {
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
  s_13_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_13_3 = {
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
  * root node
  */
  s_13_4 = {
	 .delay        = {.time_min = 0LL, .time_max = 0LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 1,
	 .description  = "C4_Analyse_3b : Data in SYN packet.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_13_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 SYN ACK reply */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_13_2, .action = 0, .target_state = &s_13_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_13(){
		 return fsm_init( &s_13_0, &s_13_1, &s_13_2, &s_13_3, EVENTS_COUNT_13 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 14======================================
 #define EVENTS_COUNT_14 2

 #define PROTO_ATTS_COUNT_14 4

 /** 865
  * Proto_atts for rule 14
  */
 
 static proto_attribute_t proto_atts_14[ PROTO_ATTS_COUNT_14 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "dest_port", .att_id = 2, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "src_port", .att_id = 1, .data_type = 0}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_14[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_14[ 2 ] ,  &proto_atts_14[ 3 ] }
	 },
	 {//event_2
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_14[ 0 ] ,  &proto_atts_14[ 1 ] ,  &proto_atts_14[ 2 ] ,  &proto_atts_14[ 3 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_14{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const char *ip_src;
	 const double *tcp_dest_port;
	 const double *tcp_src_port;
 }_msg_t_14;
 /** 592
  * Create an instance of _msg_t_14
  */
 static inline _msg_t_14* _allocate_msg_t_14(){
	 _msg_t_14 *m = mmt_mem_alloc( sizeof( _msg_t_14 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_dest_port = NULL;
	 m->tcp_src_port = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_14( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_14 *new_msg = _allocate_msg_t_14();
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
 static const uint16_t* hash_message_14( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_14 ];
	 size_t i;	 _msg_t_14 *msg = (_msg_t_14 *) data;
	 for( i=0; i<EVENTS_COUNT_14; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->tcp_dest_port != NULL && msg->tcp_src_port != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_dest_port != NULL && msg->tcp_src_port != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 14, event 1
  * TCP packet with non-authorized port number.
  */
 static inline int g_14_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_14 *his_data, *ev_data = (_msg_t_14 *) event_data;/* 61 */
	 if( unlikely( ev_data->tcp_dest_port == NULL )) return 0;
	 double tcp_dest_port = *( ev_data->tcp_dest_port );/* 61 */
	 if( unlikely( ev_data->tcp_src_port == NULL )) return 0;
	 double tcp_src_port = *( ev_data->tcp_src_port );

	 return ((check_port(tcp_dest_port) == 1) || (check_port(tcp_src_port) == 1));
 }
 
 /** 94
  * Rule 14, event 2
  * TCP packet
  */
 static inline int g_14_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_14 *his_data, *ev_data = (_msg_t_14 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->tcp_dest_port == NULL )) return 0;
	 double tcp_dest_port = *( ev_data->tcp_dest_port );/* 61 */
	 if( unlikely( ev_data->tcp_src_port == NULL )) return 0;
	 double tcp_src_port = *( ev_data->tcp_src_port );

	 return (0 != strcmp(ip_src , ip_dst) && ((tcp_dest_port + tcp_src_port) != 0));
 }
 
 /** 407
  * States of FSM for rule 14
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_14_0, s_14_1, s_14_2, s_14_3, s_14_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_14_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "C4_Analyse_3f bis: Unauthorized port number.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 TCP packet with non-authorized port number. */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_14_1, .action = 1, .target_state = &s_14_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_14_1 = {
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
  s_14_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_14_3 = {
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
  * root node
  */
  s_14_4 = {
	 .delay        = {.time_min = 0LL, .time_max = 0LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 1,
	 .description  = "C4_Analyse_3f bis: Unauthorized port number.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_14_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 TCP packet */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_14_2, .action = 0, .target_state = &s_14_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_14(){
		 return fsm_init( &s_14_0, &s_14_1, &s_14_2, &s_14_3, EVENTS_COUNT_14 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 15======================================
 #define EVENTS_COUNT_15 2

 #define PROTO_ATTS_COUNT_15 3

 /** 865
  * Proto_atts for rule 15
  */
 
 static proto_attribute_t proto_atts_15[ PROTO_ATTS_COUNT_15 ] = {{.proto = "http", .proto_id = 153, .att = "user_agent", .att_id = 7, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_15[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 1,
		 .data = (void* []) { &proto_atts_15[ 0 ] }
	 },
	 {//event_2
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_15[ 1 ] ,  &proto_atts_15[ 2 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_15{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *http_user_agent;
	 const char *ip_dst;
	 const char *ip_src;
 }_msg_t_15;
 /** 592
  * Create an instance of _msg_t_15
  */
 static inline _msg_t_15* _allocate_msg_t_15(){
	 _msg_t_15 *m = mmt_mem_alloc( sizeof( _msg_t_15 ));
	 m->http_user_agent = NULL;
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_15( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_15 *new_msg = _allocate_msg_t_15();
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i].proto_id ){/** 626 For each protocol*/
		 case 153:// protocol http
			 switch( msg->elements[i].att_id ){
			 case 7:// attribute user_agent
				 new_msg->http_user_agent = (char *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 633
			 break;
		 case 178:// protocol ip
			 switch( msg->elements[i].att_id ){
			 case 13:// attribute dst
				 new_msg->ip_dst = (char *) msg->elements[i].data;
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_15( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_15 ];
	 size_t i;	 _msg_t_15 *msg = (_msg_t_15 *) data;
	 for( i=0; i<EVENTS_COUNT_15; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->http_user_agent != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 15, event 1
  * Context: an  user agent in the HTTP header
  */
 static inline int g_15_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_15 *his_data, *ev_data = (_msg_t_15 *) event_data;/* 61 */
	 if( unlikely( ev_data->http_user_agent == NULL )) return 0;
	 const char *http_user_agent =  ev_data->http_user_agent ;

	 return (check_UA(http_user_agent) == 1);
 }
 
 /** 94
  * Rule 15, event 2
  * Trigger: Nikto detected. 
  */
 static inline int g_15_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_15 *his_data, *ev_data = (_msg_t_15 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return 0 != strcmp(ip_src , ip_dst);
 }
 
 /** 407
  * States of FSM for rule 15
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_15_0, s_15_1, s_15_2, s_15_3, s_15_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_15_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "Nikto detection",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 Context: an  user agent in the HTTP header */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_15_1, .action = 1, .target_state = &s_15_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_15_1 = {
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
  s_15_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_15_3 = {
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
  * root node
  */
  s_15_4 = {
	 .delay        = {.time_min = 0LL, .time_max = 0LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 1,
	 .description  = "Nikto detection",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_15_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 Trigger: Nikto detected.  */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_15_2, .action = 0, .target_state = &s_15_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_15(){
		 return fsm_init( &s_15_0, &s_15_1, &s_15_2, &s_15_3, EVENTS_COUNT_15 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 16======================================
 #define EVENTS_COUNT_16 2

 #define PROTO_ATTS_COUNT_16 3

 /** 865
  * Proto_atts for rule 16
  */
 
 static proto_attribute_t proto_atts_16[ PROTO_ATTS_COUNT_16 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "flags", .att_id = 6, .data_type = 0}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_16[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 3,
		 .data = (void* []) { &proto_atts_16[ 0 ] ,  &proto_atts_16[ 1 ] ,  &proto_atts_16[ 2 ] }
	 },
	 {//event_2
		 .elements_count = 3,
		 .data = (void* []) { &proto_atts_16[ 0 ] ,  &proto_atts_16[ 1 ] ,  &proto_atts_16[ 2 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_16{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const char *ip_src;
	 const double *tcp_flags;
 }_msg_t_16;
 /** 592
  * Create an instance of _msg_t_16
  */
 static inline _msg_t_16* _allocate_msg_t_16(){
	 _msg_t_16 *m = mmt_mem_alloc( sizeof( _msg_t_16 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->tcp_flags = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_16( const message_t *msg){
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
			 case 6:// attribute flags
				 new_msg->tcp_flags = (double *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_16( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_16 ];
	 size_t i;	 _msg_t_16 *msg = (_msg_t_16 *) data;
	 for( i=0; i<EVENTS_COUNT_16; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_flags != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_flags != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 16, event 1
  * SYN request
  */
 static inline int g_16_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_16 *his_data, *ev_data = (_msg_t_16 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->tcp_flags == NULL )) return 0;
	 double tcp_flags = *( ev_data->tcp_flags );

	 return ((tcp_flags == 2) && 0 != strcmp(ip_src , ip_dst));
 }
 
 /** 94
  * Rule 16, event 2
  * SYN request
  */
 static inline int g_16_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_16 *his_data, *ev_data = (_msg_t_16 *) event_data;
	 his_data = (_msg_t_16 *)fsm_get_history( fsm, 1);
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
	 double tcp_flags = *( ev_data->tcp_flags );

	 return ((tcp_flags == 2) && (0 != strcmp(ip_dst , ip_dst_1) && 0 == strcmp(ip_src , ip_src_1)));
 }
 
 /** 407
  * States of FSM for rule 16
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_16_0, s_16_1, s_16_2, s_16_3, s_16_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_16_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "Two successive TCP SYN requests but with different destination addresses.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 SYN request */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_16_1, .action = 1, .target_state = &s_16_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
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
 /** 427
  * final state
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
 }, s_16_3 = {
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
  * root node
  */
  s_16_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 10000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  = "Two successive TCP SYN requests but with different destination addresses.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_16_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 SYN request */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_16_2, .action = 0, .target_state = &s_16_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_16(){
		 return fsm_init( &s_16_0, &s_16_1, &s_16_2, &s_16_3, EVENTS_COUNT_16 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 17======================================
 #define EVENTS_COUNT_17 2

 #define PROTO_ATTS_COUNT_17 3

 /** 865
  * Proto_atts for rule 17
  */
 
 static proto_attribute_t proto_atts_17[ PROTO_ATTS_COUNT_17 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "smtp", .proto_id = 323, .att = "packet_count", .att_id = 4099, .data_type = 0}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_17[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 1,
		 .data = (void* []) { &proto_atts_17[ 2 ] }
	 },
	 {//event_2
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_17[ 0 ] ,  &proto_atts_17[ 1 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_17{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const char *ip_src;
	 const double *smtp_packet_count;
 }_msg_t_17;
 /** 592
  * Create an instance of _msg_t_17
  */
 static inline _msg_t_17* _allocate_msg_t_17(){
	 _msg_t_17 *m = mmt_mem_alloc( sizeof( _msg_t_17 ));
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->smtp_packet_count = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_17( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_17 *new_msg = _allocate_msg_t_17();
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
		 case 323:// protocol smtp
			 switch( msg->elements[i].att_id ){
			 case 4099:// attribute packet_count
				 new_msg->smtp_packet_count = (double *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_17( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_17 ];
	 size_t i;	 _msg_t_17 *msg = (_msg_t_17 *) data;
	 for( i=0; i<EVENTS_COUNT_17; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->smtp_packet_count != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 17, event 1
  * SYN request
  */
 static inline int g_17_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_17 *his_data, *ev_data = (_msg_t_17 *) event_data;/* 61 */
	 if( unlikely( ev_data->smtp_packet_count == NULL )) return 0;
	 double smtp_packet_count = *( ev_data->smtp_packet_count );

	 return (smtp_packet_count > 0);
 }
 
 /** 94
  * Rule 17, event 2
  * ip check
  */
 static inline int g_17_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_17 *his_data, *ev_data = (_msg_t_17 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return 0 != strcmp(ip_src , ip_dst);
 }
 
 /** 407
  * States of FSM for rule 17
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_17_0, s_17_1, s_17_2, s_17_3, s_17_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_17_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "SMTP detected",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 SYN request */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_17_1, .action = 1, .target_state = &s_17_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_17_1 = {
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
  s_17_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_17_3 = {
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
  * root node
  */
  s_17_4 = {
	 .delay        = {.time_min = 0LL, .time_max = 0LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 1,
	 .description  = "SMTP detected",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_17_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 ip check */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_17_2, .action = 0, .target_state = &s_17_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_17(){
		 return fsm_init( &s_17_0, &s_17_1, &s_17_2, &s_17_3, EVENTS_COUNT_17 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 18======================================
 #define EVENTS_COUNT_18 2

 #define PROTO_ATTS_COUNT_18 4

 /** 865
  * Proto_atts for rule 18
  */
 
 static proto_attribute_t proto_atts_18[ PROTO_ATTS_COUNT_18 ] = {{.proto = "gre", .proto_id = 137, .att = "proto", .att_id = 1, .data_type = 0}, {.proto = "gre", .proto_id = 137, .att = "version", .att_id = 9, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_18[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_18[ 0 ] ,  &proto_atts_18[ 1 ] }
	 },
	 {//event_2
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_18[ 2 ] ,  &proto_atts_18[ 3 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_18{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const double *gre_proto;
	 const double *gre_version;
	 const char *ip_dst;
	 const char *ip_src;
 }_msg_t_18;
 /** 592
  * Create an instance of _msg_t_18
  */
 static inline _msg_t_18* _allocate_msg_t_18(){
	 _msg_t_18 *m = mmt_mem_alloc( sizeof( _msg_t_18 ));
	 m->gre_proto = NULL;
	 m->gre_version = NULL;
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_18( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_18 *new_msg = _allocate_msg_t_18();
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i].proto_id ){/** 626 For each protocol*/
		 case 137:// protocol gre
			 switch( msg->elements[i].att_id ){
			 case 1:// attribute proto
				 new_msg->gre_proto = (double *) msg->elements[i].data;
				 break;
			 case 9:// attribute version
				 new_msg->gre_version = (double *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 633
			 break;
		 case 178:// protocol ip
			 switch( msg->elements[i].att_id ){
			 case 13:// attribute dst
				 new_msg->ip_dst = (char *) msg->elements[i].data;
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_18( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_18 ];
	 size_t i;	 _msg_t_18 *msg = (_msg_t_18 *) data;
	 for( i=0; i<EVENTS_COUNT_18; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->gre_proto != NULL && msg->gre_version != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 18, event 1
  * Context: Gre protocol
  */
 static inline int g_18_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_18 *his_data, *ev_data = (_msg_t_18 *) event_data;/* 61 */
	 if( unlikely( ev_data->gre_proto == NULL )) return 0;
	 double gre_proto = *( ev_data->gre_proto );/* 61 */
	 if( unlikely( ev_data->gre_version == NULL )) return 0;
	 double gre_version = *( ev_data->gre_version );

	 return ((gre_proto > 0) && (gre_version != 0));
 }
 
 /** 94
  * Rule 18, event 2
  * Trigger: Invalid GRE version
  */
 static inline int g_18_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_18 *his_data, *ev_data = (_msg_t_18 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return 0 != strcmp(ip_src , ip_dst);
 }
 
 /** 407
  * States of FSM for rule 18
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_18_0, s_18_1, s_18_2, s_18_3, s_18_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_18_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "Invalid GRE version detected",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 Context: Gre protocol */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_18_1, .action = 1, .target_state = &s_18_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_18_1 = {
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
  s_18_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_18_3 = {
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
  * root node
  */
  s_18_4 = {
	 .delay        = {.time_min = 0LL, .time_max = 0LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 1,
	 .description  = "Invalid GRE version detected",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_18_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 Trigger: Invalid GRE version */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_18_2, .action = 0, .target_state = &s_18_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_18(){
		 return fsm_init( &s_18_0, &s_18_1, &s_18_2, &s_18_3, EVENTS_COUNT_18 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 19======================================
 #define EVENTS_COUNT_19 2

 #define PROTO_ATTS_COUNT_19 4

 /** 865
  * Proto_atts for rule 19
  */
 
 static proto_attribute_t proto_atts_19[ PROTO_ATTS_COUNT_19 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "p_payload", .att_id = 4098, .data_type = 1}, {.proto = "tcp", .proto_id = 354, .att = "payload_len", .att_id = 23, .data_type = 0}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_19[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_19[ 2 ] ,  &proto_atts_19[ 3 ] }
	 },
	 {//event_2
		 .elements_count = 3,
		 .data = (void* []) { &proto_atts_19[ 0 ] ,  &proto_atts_19[ 1 ] ,  &proto_atts_19[ 2 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_19{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const char *ip_src;
	 const char *tcp_p_payload;
	 const double *tcp_payload_len;
 }_msg_t_19;
 /** 592
  * Create an instance of _msg_t_19
  */
 static inline _msg_t_19* _allocate_msg_t_19(){
	 _msg_t_19 *m = mmt_mem_alloc( sizeof( _msg_t_19 ));
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
 static void *convert_message_to_event_19( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_19 *new_msg = _allocate_msg_t_19();
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
				 new_msg->tcp_p_payload = (char *) msg->elements[i].data;
				 break;
			 case 23:// attribute payload_len
				 new_msg->tcp_payload_len = (double *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_19( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_19 ];
	 size_t i;	 _msg_t_19 *msg = (_msg_t_19 *) data;
	 for( i=0; i<EVENTS_COUNT_19; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->tcp_p_payload != NULL && msg->tcp_payload_len != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_src != NULL && msg->tcp_p_payload != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 19, event 1
  * Context: Here it is a TCP segment
  */
 static inline int g_19_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_19 *his_data, *ev_data = (_msg_t_19 *) event_data;/* 61 */
	 if( unlikely( ev_data->tcp_p_payload == NULL )) return 0;
	 const char *tcp_p_payload =  ev_data->tcp_p_payload ;/* 61 */
	 if( unlikely( ev_data->tcp_payload_len == NULL )) return 0;
	 double tcp_payload_len = *( ev_data->tcp_payload_len );

	 return ((tcp_payload_len > 0) && (check_sql_injection(tcp_p_payload , tcp_payload_len) == 1));
 }
 
 /** 94
  * Rule 19, event 2
  * Trigger: SQL Injection in the payload
  */
 static inline int g_19_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_19 *his_data, *ev_data = (_msg_t_19 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->tcp_p_payload == NULL )) return 0;
	 const char *tcp_p_payload =  ev_data->tcp_p_payload ;

	 return (0 != strcmp(ip_src , ip_dst) && 0 == strcmp(tcp_p_payload , tcp_p_payload));
 }
 
 /** 407
  * States of FSM for rule 19
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_19_0, s_19_1, s_19_2, s_19_3, s_19_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_19_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "SQL Injection detected",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 Context: Here it is a TCP segment */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_19_1, .action = 1, .target_state = &s_19_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_19_1 = {
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
  s_19_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_19_3 = {
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
  * root node
  */
  s_19_4 = {
	 .delay        = {.time_min = 0LL, .time_max = 0LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 1,
	 .description  = "SQL Injection detected",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_19_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 Trigger: SQL Injection in the payload */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_19_2, .action = 0, .target_state = &s_19_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_19(){
		 return fsm_init( &s_19_0, &s_19_1, &s_19_2, &s_19_3, EVENTS_COUNT_19 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 20======================================
 #define EVENTS_COUNT_20 4

 #define PROTO_ATTS_COUNT_20 3

 /** 865
  * Proto_atts for rule 20
  */
 
 static proto_attribute_t proto_atts_20[ PROTO_ATTS_COUNT_20 ] = {{.proto = "icmp", .proto_id = 163, .att = "type", .att_id = 1, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_20[ 5 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 3,
		 .data = (void* []) { &proto_atts_20[ 0 ] ,  &proto_atts_20[ 1 ] ,  &proto_atts_20[ 2 ] }
	 },
	 {//event_2
		 .elements_count = 3,
		 .data = (void* []) { &proto_atts_20[ 0 ] ,  &proto_atts_20[ 1 ] ,  &proto_atts_20[ 2 ] }
	 },
	 {//event_3
		 .elements_count = 3,
		 .data = (void* []) { &proto_atts_20[ 0 ] ,  &proto_atts_20[ 1 ] ,  &proto_atts_20[ 2 ] }
	 },
	 {//event_4
		 .elements_count = 3,
		 .data = (void* []) { &proto_atts_20[ 0 ] ,  &proto_atts_20[ 1 ] ,  &proto_atts_20[ 2 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_20{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const double *icmp_type;
	 const char *ip_dst;
	 const char *ip_src;
 }_msg_t_20;
 /** 592
  * Create an instance of _msg_t_20
  */
 static inline _msg_t_20* _allocate_msg_t_20(){
	 _msg_t_20 *m = mmt_mem_alloc( sizeof( _msg_t_20 ));
	 m->icmp_type = NULL;
	 m->ip_dst = NULL;
	 m->ip_src = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_20( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_20 *new_msg = _allocate_msg_t_20();
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i].proto_id ){/** 626 For each protocol*/
		 case 163:// protocol icmp
			 switch( msg->elements[i].att_id ){
			 case 1:// attribute type
				 new_msg->icmp_type = (double *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 633
			 break;
		 case 178:// protocol ip
			 switch( msg->elements[i].att_id ){
			 case 13:// attribute dst
				 new_msg->ip_dst = (char *) msg->elements[i].data;
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_20( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_20 ];
	 size_t i;	 _msg_t_20 *msg = (_msg_t_20 *) data;
	 for( i=0; i<EVENTS_COUNT_20; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->icmp_type != NULL && msg->ip_dst != NULL && msg->ip_src != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->icmp_type != NULL && msg->ip_dst != NULL && msg->ip_src != NULL )
		 hash_table[ 1 ] = 2;
	 if( msg->icmp_type != NULL && msg->ip_dst != NULL && msg->ip_src != NULL )
		 hash_table[ 2 ] = 3;
	 if( msg->icmp_type != NULL && msg->ip_dst != NULL && msg->ip_src != NULL )
		 hash_table[ 3 ] = 4;
	 return hash_table;
 }
 /** 94
  * Rule 20, event 1
  * Context: ICMP redirect
  */
 static inline int g_20_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_20 *his_data, *ev_data = (_msg_t_20 *) event_data;/* 61 */
	 if( unlikely( ev_data->icmp_type == NULL )) return 0;
	 double icmp_type = *( ev_data->icmp_type );/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return ((icmp_type == 5) && 0 != strcmp(ip_dst , ip_src));
 }
 
 /** 94
  * Rule 20, event 2
  * Trigger: 2nd consecutive ICMP redirect packet
  */
 static inline int g_20_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_20 *his_data, *ev_data = (_msg_t_20 *) event_data;/* 61 */
	 if( unlikely( ev_data->icmp_type == NULL )) return 0;
	 double icmp_type = *( ev_data->icmp_type );
	 his_data = (_msg_t_20 *)fsm_get_history( fsm, 2);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_dst == NULL )) return 0;
	 const char *ip_dst_2 =  his_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( his_data->ip_src == NULL )) return 0;
	 const char *ip_src_2 =  his_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return ((icmp_type == 5) && (0 == strcmp(ip_dst , ip_dst_2) && 0 == strcmp(ip_src , ip_src_2)));
 }
 
 /** 94
  * Rule 20, event 3
  * Trigger: 3rd consecutive ICMP redirect packet
  */
 static inline int g_20_3( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_20 *his_data, *ev_data = (_msg_t_20 *) event_data;/* 61 */
	 if( unlikely( ev_data->icmp_type == NULL )) return 0;
	 double icmp_type = *( ev_data->icmp_type );
	 his_data = (_msg_t_20 *)fsm_get_history( fsm, 2);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_dst == NULL )) return 0;
	 const char *ip_dst_2 =  his_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( his_data->ip_src == NULL )) return 0;
	 const char *ip_src_2 =  his_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return ((icmp_type == 5) && (0 == strcmp(ip_dst , ip_dst_2) && 0 == strcmp(ip_src , ip_src_2)));
 }
 
 /** 94
  * Rule 20, event 4
  * Trigger: 4th consecutive ICMP redirect packet
  */
 static inline int g_20_4( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_20 *his_data, *ev_data = (_msg_t_20 *) event_data;/* 61 */
	 if( unlikely( ev_data->icmp_type == NULL )) return 0;
	 double icmp_type = *( ev_data->icmp_type );
	 his_data = (_msg_t_20 *)fsm_get_history( fsm, 2);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_dst == NULL )) return 0;
	 const char *ip_dst_2 =  his_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( his_data->ip_src == NULL )) return 0;
	 const char *ip_src_2 =  his_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return ((icmp_type == 5) && (0 == strcmp(ip_dst , ip_dst_2) && 0 == strcmp(ip_src , ip_src_2)));
 }
 
 /** 407
  * States of FSM for rule 20
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_20_0, s_20_1, s_20_2, s_20_3, s_20_4, s_20_5, s_20_6;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_20_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "4 consecutive ICMP redirect packets. Possibly ICMP redirect flood.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 Context: ICMP redirect */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_20_1, .action = 1, .target_state = &s_20_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_20_1 = {
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
  s_20_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_20_3 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_20_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 3000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_20_3}, //FSM_ACTION_DO_NOTHING
		 /** 456 Trigger: 2nd consecutive ICMP redirect packet */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_20_2, .action = 1, .target_state = &s_20_5}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 2
 },
 /** 427
  * root node
  */
  s_20_5 = {
	 .delay        = {.time_min = 0LL, .time_max = 6000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  = "4 consecutive ICMP redirect packets. Possibly ICMP redirect flood.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_20_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 Trigger: 3rd consecutive ICMP redirect packet */
		 /** 458 A real event */
		 { .event_type = 3, .guard = &g_20_3, .action = 1, .target_state = &s_20_6}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 2
 }, s_20_6 = {
	 .delay        = {.time_min = 1LL, .time_max = 3000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_20_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 Trigger: 4th consecutive ICMP redirect packet */
		 /** 458 A real event */
		 { .event_type = 4, .guard = &g_20_4, .action = 0, .target_state = &s_20_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_20(){
		 return fsm_init( &s_20_0, &s_20_1, &s_20_2, &s_20_3, EVENTS_COUNT_20 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 21======================================
 #define EVENTS_COUNT_21 2

 #define PROTO_ATTS_COUNT_21 5

 /** 865
  * Proto_atts for rule 21
  */
 
 static proto_attribute_t proto_atts_21[ PROTO_ATTS_COUNT_21 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "frag_offset", .att_id = 8, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "identification", .att_id = 5, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "mf_flag", .att_id = 7, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_21[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 5,
		 .data = (void* []) { &proto_atts_21[ 0 ] ,  &proto_atts_21[ 1 ] ,  &proto_atts_21[ 2 ] ,  &proto_atts_21[ 3 ] ,  &proto_atts_21[ 4 ] }
	 },
	 {//event_2
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_21[ 0 ] ,  &proto_atts_21[ 1 ] ,  &proto_atts_21[ 2 ] ,  &proto_atts_21[ 4 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_21{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const double *ip_frag_offset;
	 const double *ip_identification;
	 const double *ip_mf_flag;
	 const char *ip_src;
 }_msg_t_21;
 /** 592
  * Create an instance of _msg_t_21
  */
 static inline _msg_t_21* _allocate_msg_t_21(){
	 _msg_t_21 *m = mmt_mem_alloc( sizeof( _msg_t_21 ));
	 m->ip_dst = NULL;
	 m->ip_frag_offset = NULL;
	 m->ip_identification = NULL;
	 m->ip_mf_flag = NULL;
	 m->ip_src = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_21( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_21 *new_msg = _allocate_msg_t_21();
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
			 case 8:// attribute frag_offset
				 new_msg->ip_frag_offset = (double *) msg->elements[i].data;
				 break;
			 case 5:// attribute identification
				 new_msg->ip_identification = (double *) msg->elements[i].data;
				 break;
			 case 7:// attribute mf_flag
				 new_msg->ip_mf_flag = (double *) msg->elements[i].data;
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_21( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_21 ];
	 size_t i;	 _msg_t_21 *msg = (_msg_t_21 *) data;
	 for( i=0; i<EVENTS_COUNT_21; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->ip_dst != NULL && msg->ip_frag_offset != NULL && msg->ip_identification != NULL && msg->ip_mf_flag != NULL && msg->ip_src != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_frag_offset != NULL && msg->ip_identification != NULL && msg->ip_src != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 21, event 1
  * IP fragment with offset = 0 followed by another
  */
 static inline int g_21_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_21 *his_data, *ev_data = (_msg_t_21 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_frag_offset == NULL )) return 0;
	 double ip_frag_offset = *( ev_data->ip_frag_offset );/* 61 */
	 if( unlikely( ev_data->ip_identification == NULL )) return 0;
	 double ip_identification = *( ev_data->ip_identification );/* 61 */
	 if( unlikely( ev_data->ip_mf_flag == NULL )) return 0;
	 double ip_mf_flag = *( ev_data->ip_mf_flag );/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return ((ip_identification > 0) && ((ip_mf_flag == 1) && ((ip_frag_offset == 0) && 0 != strcmp(ip_src , ip_dst))));
 }
 
 /** 94
  * Rule 21, event 2
  * IP fragment with same identification and an offset = 0
  */
 static inline int g_21_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_21 *his_data, *ev_data = (_msg_t_21 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_frag_offset == NULL )) return 0;
	 double ip_frag_offset = *( ev_data->ip_frag_offset );
	 his_data = (_msg_t_21 *)fsm_get_history( fsm, 1);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_identification == NULL )) return 0;
	 double ip_identification_1 = *( his_data->ip_identification );/* 61 */
	 if( unlikely( ev_data->ip_identification == NULL )) return 0;
	 double ip_identification = *( ev_data->ip_identification );/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return ((ip_identification == ip_identification_1) && ((ip_frag_offset == 0) && 0 != strcmp(ip_src , ip_dst)));
 }
 
 /** 407
  * States of FSM for rule 21
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_21_0, s_21_1, s_21_2, s_21_3, s_21_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_21_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "IP fragmentation : fragments with offset always = 0 (allowed but could be an evasion).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 IP fragment with offset = 0 followed by another */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_21_1, .action = 1, .target_state = &s_21_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_21_1 = {
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
  s_21_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_21_3 = {
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
  * root node
  */
  s_21_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 1000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  = "IP fragmentation : fragments with offset always = 0 (allowed but could be an evasion).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_21_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 IP fragment with same identification and an offset = 0 */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_21_2, .action = 0, .target_state = &s_21_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_21(){
		 return fsm_init( &s_21_0, &s_21_1, &s_21_2, &s_21_3, EVENTS_COUNT_21 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 22======================================
 #define EVENTS_COUNT_22 2

 #define PROTO_ATTS_COUNT_22 5

 /** 865
  * Proto_atts for rule 22
  */
 
 static proto_attribute_t proto_atts_22[ PROTO_ATTS_COUNT_22 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "frag_offset", .att_id = 8, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "identification", .att_id = 5, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "mf_flag", .att_id = 7, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_22[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 5,
		 .data = (void* []) { &proto_atts_22[ 0 ] ,  &proto_atts_22[ 1 ] ,  &proto_atts_22[ 2 ] ,  &proto_atts_22[ 3 ] ,  &proto_atts_22[ 4 ] }
	 },
	 {//event_2
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_22[ 0 ] ,  &proto_atts_22[ 1 ] ,  &proto_atts_22[ 2 ] ,  &proto_atts_22[ 4 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_22{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const double *ip_frag_offset;
	 const double *ip_identification;
	 const double *ip_mf_flag;
	 const char *ip_src;
 }_msg_t_22;
 /** 592
  * Create an instance of _msg_t_22
  */
 static inline _msg_t_22* _allocate_msg_t_22(){
	 _msg_t_22 *m = mmt_mem_alloc( sizeof( _msg_t_22 ));
	 m->ip_dst = NULL;
	 m->ip_frag_offset = NULL;
	 m->ip_identification = NULL;
	 m->ip_mf_flag = NULL;
	 m->ip_src = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_22( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_22 *new_msg = _allocate_msg_t_22();
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
			 case 8:// attribute frag_offset
				 new_msg->ip_frag_offset = (double *) msg->elements[i].data;
				 break;
			 case 5:// attribute identification
				 new_msg->ip_identification = (double *) msg->elements[i].data;
				 break;
			 case 7:// attribute mf_flag
				 new_msg->ip_mf_flag = (double *) msg->elements[i].data;
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_22( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_22 ];
	 size_t i;	 _msg_t_22 *msg = (_msg_t_22 *) data;
	 for( i=0; i<EVENTS_COUNT_22; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->ip_dst != NULL && msg->ip_frag_offset != NULL && msg->ip_identification != NULL && msg->ip_mf_flag != NULL && msg->ip_src != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_frag_offset != NULL && msg->ip_identification != NULL && msg->ip_src != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 22, event 1
  * IP fragment followed by another
  */
 static inline int g_22_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_22 *his_data, *ev_data = (_msg_t_22 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_frag_offset == NULL )) return 0;
	 double ip_frag_offset = *( ev_data->ip_frag_offset );/* 61 */
	 if( unlikely( ev_data->ip_identification == NULL )) return 0;
	 double ip_identification = *( ev_data->ip_identification );/* 61 */
	 if( unlikely( ev_data->ip_mf_flag == NULL )) return 0;
	 double ip_mf_flag = *( ev_data->ip_mf_flag );/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return ((ip_identification > 0) && ((ip_mf_flag == 1) && ((ip_frag_offset >= 0) && 0 != strcmp(ip_src , ip_dst))));
 }
 
 /** 94
  * Rule 22, event 2
  * IP fragment with same identification and an offset less than 9 bytes
  */
 static inline int g_22_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_22 *his_data, *ev_data = (_msg_t_22 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;
	 his_data = (_msg_t_22 *)fsm_get_history( fsm, 1);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_frag_offset == NULL )) return 0;
	 double ip_frag_offset_1 = *( his_data->ip_frag_offset );/* 61 */
	 if( unlikely( ev_data->ip_frag_offset == NULL )) return 0;
	 double ip_frag_offset = *( ev_data->ip_frag_offset );/* 61 */
	 if( unlikely( his_data->ip_identification == NULL )) return 0;
	 double ip_identification_1 = *( his_data->ip_identification );/* 61 */
	 if( unlikely( ev_data->ip_identification == NULL )) return 0;
	 double ip_identification = *( ev_data->ip_identification );/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return ((ip_identification == ip_identification_1) && ((ip_frag_offset > ip_frag_offset_1) && (((ip_frag_offset - ip_frag_offset_1) < 9) && 0 != strcmp(ip_src , ip_dst))));
 }
 
 /** 407
  * States of FSM for rule 22
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_22_0, s_22_1, s_22_2, s_22_3, s_22_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_22_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "IP fragmentation : a fragment with a size less than 9 bytes (allowed but could be an evasion).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 IP fragment followed by another */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_22_1, .action = 1, .target_state = &s_22_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_22_1 = {
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
  s_22_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_22_3 = {
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
  * root node
  */
  s_22_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 1000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  = "IP fragmentation : a fragment with a size less than 9 bytes (allowed but could be an evasion).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_22_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 IP fragment with same identification and an offset less than 9 bytes */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_22_2, .action = 0, .target_state = &s_22_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_22(){
		 return fsm_init( &s_22_0, &s_22_1, &s_22_2, &s_22_3, EVENTS_COUNT_22 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 23======================================
 #define EVENTS_COUNT_23 2

 #define PROTO_ATTS_COUNT_23 5

 /** 865
  * Proto_atts for rule 23
  */
 
 static proto_attribute_t proto_atts_23[ PROTO_ATTS_COUNT_23 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "frag_offset", .att_id = 8, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "identification", .att_id = 5, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "mf_flag", .att_id = 7, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_23[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 5,
		 .data = (void* []) { &proto_atts_23[ 0 ] ,  &proto_atts_23[ 1 ] ,  &proto_atts_23[ 2 ] ,  &proto_atts_23[ 3 ] ,  &proto_atts_23[ 4 ] }
	 },
	 {//event_2
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_23[ 0 ] ,  &proto_atts_23[ 1 ] ,  &proto_atts_23[ 2 ] ,  &proto_atts_23[ 4 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_23{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const double *ip_frag_offset;
	 const double *ip_identification;
	 const double *ip_mf_flag;
	 const char *ip_src;
 }_msg_t_23;
 /** 592
  * Create an instance of _msg_t_23
  */
 static inline _msg_t_23* _allocate_msg_t_23(){
	 _msg_t_23 *m = mmt_mem_alloc( sizeof( _msg_t_23 ));
	 m->ip_dst = NULL;
	 m->ip_frag_offset = NULL;
	 m->ip_identification = NULL;
	 m->ip_mf_flag = NULL;
	 m->ip_src = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_23( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_23 *new_msg = _allocate_msg_t_23();
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
			 case 8:// attribute frag_offset
				 new_msg->ip_frag_offset = (double *) msg->elements[i].data;
				 break;
			 case 5:// attribute identification
				 new_msg->ip_identification = (double *) msg->elements[i].data;
				 break;
			 case 7:// attribute mf_flag
				 new_msg->ip_mf_flag = (double *) msg->elements[i].data;
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_23( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_23 ];
	 size_t i;	 _msg_t_23 *msg = (_msg_t_23 *) data;
	 for( i=0; i<EVENTS_COUNT_23; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->ip_dst != NULL && msg->ip_frag_offset != NULL && msg->ip_identification != NULL && msg->ip_mf_flag != NULL && msg->ip_src != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_frag_offset != NULL && msg->ip_identification != NULL && msg->ip_src != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 23, event 1
  * IP fragment followed by another
  */
 static inline int g_23_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_23 *his_data, *ev_data = (_msg_t_23 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_frag_offset == NULL )) return 0;
	 double ip_frag_offset = *( ev_data->ip_frag_offset );/* 61 */
	 if( unlikely( ev_data->ip_identification == NULL )) return 0;
	 double ip_identification = *( ev_data->ip_identification );/* 61 */
	 if( unlikely( ev_data->ip_mf_flag == NULL )) return 0;
	 double ip_mf_flag = *( ev_data->ip_mf_flag );/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return ((ip_identification > 0) && ((ip_mf_flag == 1) && ((ip_frag_offset >= 0) && 0 != strcmp(ip_src , ip_dst))));
 }
 
 /** 94
  * Rule 23, event 2
  * IP fragment with same identification and an offset less than 9 bytes
  */
 static inline int g_23_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_23 *his_data, *ev_data = (_msg_t_23 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;
	 his_data = (_msg_t_23 *)fsm_get_history( fsm, 1);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_frag_offset == NULL )) return 0;
	 double ip_frag_offset_1 = *( his_data->ip_frag_offset );/* 61 */
	 if( unlikely( ev_data->ip_frag_offset == NULL )) return 0;
	 double ip_frag_offset = *( ev_data->ip_frag_offset );/* 61 */
	 if( unlikely( his_data->ip_identification == NULL )) return 0;
	 double ip_identification_1 = *( his_data->ip_identification );/* 61 */
	 if( unlikely( ev_data->ip_identification == NULL )) return 0;
	 double ip_identification = *( ev_data->ip_identification );/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return ((ip_identification == ip_identification_1) && ((ip_frag_offset < ip_frag_offset_1) && (((ip_frag_offset_1 - ip_frag_offset) < 9) && 0 != strcmp(ip_src , ip_dst))));
 }
 
 /** 407
  * States of FSM for rule 23
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_23_0, s_23_1, s_23_2, s_23_3, s_23_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_23_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "Out of order IP fragmentation : a fragment with a size less than 9 bytes (allowed but could be an evasion).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 IP fragment followed by another */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_23_1, .action = 1, .target_state = &s_23_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_23_1 = {
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
  s_23_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_23_3 = {
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
  * root node
  */
  s_23_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 1000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  = "Out of order IP fragmentation : a fragment with a size less than 9 bytes (allowed but could be an evasion).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_23_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 IP fragment with same identification and an offset less than 9 bytes */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_23_2, .action = 0, .target_state = &s_23_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_23(){
		 return fsm_init( &s_23_0, &s_23_1, &s_23_2, &s_23_3, EVENTS_COUNT_23 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 24======================================
 #define EVENTS_COUNT_24 2

 #define PROTO_ATTS_COUNT_24 6

 /** 865
  * Proto_atts for rule 24
  */
 
 static proto_attribute_t proto_atts_24[ PROTO_ATTS_COUNT_24 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "frag_offset", .att_id = 8, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "identification", .att_id = 5, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "mf_flag", .att_id = 7, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "tot_len", .att_id = 4, .data_type = 0}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_24[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 5,
		 .data = (void* []) { &proto_atts_24[ 0 ] ,  &proto_atts_24[ 1 ] ,  &proto_atts_24[ 2 ] ,  &proto_atts_24[ 3 ] ,  &proto_atts_24[ 4 ] }
	 },
	 {//event_2
		 .elements_count = 5,
		 .data = (void* []) { &proto_atts_24[ 0 ] ,  &proto_atts_24[ 1 ] ,  &proto_atts_24[ 2 ] ,  &proto_atts_24[ 4 ] ,  &proto_atts_24[ 5 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_24{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const double *ip_frag_offset;
	 const double *ip_identification;
	 const double *ip_mf_flag;
	 const char *ip_src;
	 const double *ip_tot_len;
 }_msg_t_24;
 /** 592
  * Create an instance of _msg_t_24
  */
 static inline _msg_t_24* _allocate_msg_t_24(){
	 _msg_t_24 *m = mmt_mem_alloc( sizeof( _msg_t_24 ));
	 m->ip_dst = NULL;
	 m->ip_frag_offset = NULL;
	 m->ip_identification = NULL;
	 m->ip_mf_flag = NULL;
	 m->ip_src = NULL;
	 m->ip_tot_len = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_24( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_24 *new_msg = _allocate_msg_t_24();
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
			 case 8:// attribute frag_offset
				 new_msg->ip_frag_offset = (double *) msg->elements[i].data;
				 break;
			 case 5:// attribute identification
				 new_msg->ip_identification = (double *) msg->elements[i].data;
				 break;
			 case 7:// attribute mf_flag
				 new_msg->ip_mf_flag = (double *) msg->elements[i].data;
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) msg->elements[i].data;
				 break;
			 case 4:// attribute tot_len
				 new_msg->ip_tot_len = (double *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_24( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_24 ];
	 size_t i;	 _msg_t_24 *msg = (_msg_t_24 *) data;
	 for( i=0; i<EVENTS_COUNT_24; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->ip_dst != NULL && msg->ip_frag_offset != NULL && msg->ip_identification != NULL && msg->ip_mf_flag != NULL && msg->ip_src != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_frag_offset != NULL && msg->ip_identification != NULL && msg->ip_src != NULL && msg->ip_tot_len != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 24, event 1
  * IP fragment followed by another
  */
 static inline int g_24_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_24 *his_data, *ev_data = (_msg_t_24 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_frag_offset == NULL )) return 0;
	 double ip_frag_offset = *( ev_data->ip_frag_offset );/* 61 */
	 if( unlikely( ev_data->ip_identification == NULL )) return 0;
	 double ip_identification = *( ev_data->ip_identification );/* 61 */
	 if( unlikely( ev_data->ip_mf_flag == NULL )) return 0;
	 double ip_mf_flag = *( ev_data->ip_mf_flag );/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return ((ip_identification > 0) && ((ip_mf_flag == 1) && ((ip_frag_offset >= 0) && 0 != strcmp(ip_src , ip_dst))));
 }
 
 /** 94
  * Rule 24, event 2
  * IP fragment with same identification and diffenrences in offsets less than length
  */
 static inline int g_24_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_24 *his_data, *ev_data = (_msg_t_24 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;
	 his_data = (_msg_t_24 *)fsm_get_history( fsm, 1);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_frag_offset == NULL )) return 0;
	 double ip_frag_offset_1 = *( his_data->ip_frag_offset );/* 61 */
	 if( unlikely( ev_data->ip_frag_offset == NULL )) return 0;
	 double ip_frag_offset = *( ev_data->ip_frag_offset );/* 61 */
	 if( unlikely( his_data->ip_identification == NULL )) return 0;
	 double ip_identification_1 = *( his_data->ip_identification );/* 61 */
	 if( unlikely( ev_data->ip_identification == NULL )) return 0;
	 double ip_identification = *( ev_data->ip_identification );/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->ip_tot_len == NULL )) return 0;
	 double ip_tot_len = *( ev_data->ip_tot_len );

	 return ((ip_identification == ip_identification_1) && ((ip_frag_offset > ip_frag_offset_1) && (((ip_frag_offset - ip_frag_offset_1) < ip_tot_len) && 0 != strcmp(ip_src , ip_dst))));
 }
 
 /** 407
  * States of FSM for rule 24
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_24_0, s_24_1, s_24_2, s_24_3, s_24_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_24_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "Overlapping IP fragmentation : difference in offset of concomitant fragments less than fragment length (allowed but could be an evasion).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 IP fragment followed by another */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_24_1, .action = 1, .target_state = &s_24_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_24_1 = {
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
  s_24_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_24_3 = {
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
  * root node
  */
  s_24_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 1000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  = "Overlapping IP fragmentation : difference in offset of concomitant fragments less than fragment length (allowed but could be an evasion).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_24_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 IP fragment with same identification and diffenrences in offsets less than length */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_24_2, .action = 0, .target_state = &s_24_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_24(){
		 return fsm_init( &s_24_0, &s_24_1, &s_24_2, &s_24_3, EVENTS_COUNT_24 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 25======================================
 #define EVENTS_COUNT_25 2

 #define PROTO_ATTS_COUNT_25 6

 /** 865
  * Proto_atts for rule 25
  */
 
 static proto_attribute_t proto_atts_25[ PROTO_ATTS_COUNT_25 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "frag_offset", .att_id = 8, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "identification", .att_id = 5, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "mf_flag", .att_id = 7, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "tot_len", .att_id = 4, .data_type = 0}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_25[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 5,
		 .data = (void* []) { &proto_atts_25[ 0 ] ,  &proto_atts_25[ 1 ] ,  &proto_atts_25[ 2 ] ,  &proto_atts_25[ 3 ] ,  &proto_atts_25[ 4 ] }
	 },
	 {//event_2
		 .elements_count = 5,
		 .data = (void* []) { &proto_atts_25[ 0 ] ,  &proto_atts_25[ 1 ] ,  &proto_atts_25[ 2 ] ,  &proto_atts_25[ 4 ] ,  &proto_atts_25[ 5 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_25{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const double *ip_frag_offset;
	 const double *ip_identification;
	 const double *ip_mf_flag;
	 const char *ip_src;
	 const double *ip_tot_len;
 }_msg_t_25;
 /** 592
  * Create an instance of _msg_t_25
  */
 static inline _msg_t_25* _allocate_msg_t_25(){
	 _msg_t_25 *m = mmt_mem_alloc( sizeof( _msg_t_25 ));
	 m->ip_dst = NULL;
	 m->ip_frag_offset = NULL;
	 m->ip_identification = NULL;
	 m->ip_mf_flag = NULL;
	 m->ip_src = NULL;
	 m->ip_tot_len = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_25( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_25 *new_msg = _allocate_msg_t_25();
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
			 case 8:// attribute frag_offset
				 new_msg->ip_frag_offset = (double *) msg->elements[i].data;
				 break;
			 case 5:// attribute identification
				 new_msg->ip_identification = (double *) msg->elements[i].data;
				 break;
			 case 7:// attribute mf_flag
				 new_msg->ip_mf_flag = (double *) msg->elements[i].data;
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) msg->elements[i].data;
				 break;
			 case 4:// attribute tot_len
				 new_msg->ip_tot_len = (double *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_25( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_25 ];
	 size_t i;	 _msg_t_25 *msg = (_msg_t_25 *) data;
	 for( i=0; i<EVENTS_COUNT_25; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->ip_dst != NULL && msg->ip_frag_offset != NULL && msg->ip_identification != NULL && msg->ip_mf_flag != NULL && msg->ip_src != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_frag_offset != NULL && msg->ip_identification != NULL && msg->ip_src != NULL && msg->ip_tot_len != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 25, event 1
  * IP fragment followed by another
  */
 static inline int g_25_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_25 *his_data, *ev_data = (_msg_t_25 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_frag_offset == NULL )) return 0;
	 double ip_frag_offset = *( ev_data->ip_frag_offset );/* 61 */
	 if( unlikely( ev_data->ip_identification == NULL )) return 0;
	 double ip_identification = *( ev_data->ip_identification );/* 61 */
	 if( unlikely( ev_data->ip_mf_flag == NULL )) return 0;
	 double ip_mf_flag = *( ev_data->ip_mf_flag );/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return ((ip_identification > 0) && ((ip_mf_flag == 1) && ((ip_frag_offset >= 0) && 0 != strcmp(ip_src , ip_dst))));
 }
 
 /** 94
  * Rule 25, event 2
  * IP fragment with same identification and diffenrences in offsets less than length
  */
 static inline int g_25_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_25 *his_data, *ev_data = (_msg_t_25 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;
	 his_data = (_msg_t_25 *)fsm_get_history( fsm, 1);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_frag_offset == NULL )) return 0;
	 double ip_frag_offset_1 = *( his_data->ip_frag_offset );/* 61 */
	 if( unlikely( ev_data->ip_frag_offset == NULL )) return 0;
	 double ip_frag_offset = *( ev_data->ip_frag_offset );/* 61 */
	 if( unlikely( his_data->ip_identification == NULL )) return 0;
	 double ip_identification_1 = *( his_data->ip_identification );/* 61 */
	 if( unlikely( ev_data->ip_identification == NULL )) return 0;
	 double ip_identification = *( ev_data->ip_identification );/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->ip_tot_len == NULL )) return 0;
	 double ip_tot_len = *( ev_data->ip_tot_len );

	 return ((ip_identification == ip_identification_1) && ((ip_frag_offset < ip_frag_offset_1) && (((ip_frag_offset_1 - ip_frag_offset) < ip_tot_len) && 0 != strcmp(ip_src , ip_dst))));
 }
 
 /** 407
  * States of FSM for rule 25
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_25_0, s_25_1, s_25_2, s_25_3, s_25_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_25_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "Overlapping unordered IP fragmentation : difference in offset of concomitant fragments less than fragment length (allowed but could be an evasion).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 IP fragment followed by another */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_25_1, .action = 1, .target_state = &s_25_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_25_1 = {
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
  s_25_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_25_3 = {
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
  * root node
  */
  s_25_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 1000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  = "Overlapping unordered IP fragmentation : difference in offset of concomitant fragments less than fragment length (allowed but could be an evasion).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_25_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 IP fragment with same identification and diffenrences in offsets less than length */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_25_2, .action = 0, .target_state = &s_25_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_25(){
		 return fsm_init( &s_25_0, &s_25_1, &s_25_2, &s_25_3, EVENTS_COUNT_25 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 26======================================
 #define EVENTS_COUNT_26 4

 #define PROTO_ATTS_COUNT_26 3

 /** 865
  * Proto_atts for rule 26
  */
 
 static proto_attribute_t proto_atts_26[ PROTO_ATTS_COUNT_26 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "proto_id", .att_id = 10, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_26[ 5 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 3,
		 .data = (void* []) { &proto_atts_26[ 0 ] ,  &proto_atts_26[ 1 ] ,  &proto_atts_26[ 2 ] }
	 },
	 {//event_2
		 .elements_count = 3,
		 .data = (void* []) { &proto_atts_26[ 0 ] ,  &proto_atts_26[ 1 ] ,  &proto_atts_26[ 2 ] }
	 },
	 {//event_3
		 .elements_count = 3,
		 .data = (void* []) { &proto_atts_26[ 0 ] ,  &proto_atts_26[ 1 ] ,  &proto_atts_26[ 2 ] }
	 },
	 {//event_4
		 .elements_count = 3,
		 .data = (void* []) { &proto_atts_26[ 0 ] ,  &proto_atts_26[ 1 ] ,  &proto_atts_26[ 2 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_26{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const double *ip_proto_id;
	 const char *ip_src;
 }_msg_t_26;
 /** 592
  * Create an instance of _msg_t_26
  */
 static inline _msg_t_26* _allocate_msg_t_26(){
	 _msg_t_26 *m = mmt_mem_alloc( sizeof( _msg_t_26 ));
	 m->ip_dst = NULL;
	 m->ip_proto_id = NULL;
	 m->ip_src = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_26( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_26 *new_msg = _allocate_msg_t_26();
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
			 case 10:// attribute proto_id
				 new_msg->ip_proto_id = (double *) msg->elements[i].data;
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_26( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_26 ];
	 size_t i;	 _msg_t_26 *msg = (_msg_t_26 *) data;
	 for( i=0; i<EVENTS_COUNT_26; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->ip_dst != NULL && msg->ip_proto_id != NULL && msg->ip_src != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_proto_id != NULL && msg->ip_src != NULL )
		 hash_table[ 1 ] = 2;
	 if( msg->ip_dst != NULL && msg->ip_proto_id != NULL && msg->ip_src != NULL )
		 hash_table[ 2 ] = 3;
	 if( msg->ip_dst != NULL && msg->ip_proto_id != NULL && msg->ip_src != NULL )
		 hash_table[ 3 ] = 4;
	 return hash_table;
 }
 /** 94
  * Rule 26, event 1
  * IP packet header with the eight-bit IP protocol field set (1)
  */
 static inline int g_26_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_26 *his_data, *ev_data = (_msg_t_26 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_proto_id == NULL )) return 0;
	 double ip_proto_id = *( ev_data->ip_proto_id );/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return ((ip_proto_id != 0) && 0 != strcmp(ip_src , ip_dst));
 }
 
 /** 94
  * Rule 26, event 2
  * IP packet header with another eight-bit IP protocol field set (2)
  */
 static inline int g_26_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_26 *his_data, *ev_data = (_msg_t_26 *) event_data;
	 his_data = (_msg_t_26 *)fsm_get_history( fsm, 1);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_dst == NULL )) return 0;
	 const char *ip_dst_1 =  his_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( his_data->ip_proto_id == NULL )) return 0;
	 double ip_proto_id_1 = *( his_data->ip_proto_id );/* 61 */
	 if( unlikely( ev_data->ip_proto_id == NULL )) return 0;
	 double ip_proto_id = *( ev_data->ip_proto_id );/* 61 */
	 if( unlikely( his_data->ip_src == NULL )) return 0;
	 const char *ip_src_1 =  his_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return ((ip_proto_id != ip_proto_id_1) && (0 == strcmp(ip_dst , ip_dst_1) && 0 == strcmp(ip_src , ip_src_1)));
 }
 
 /** 94
  * Rule 26, event 3
  * IP packet header with another eight-bit IP protocol field set (3)
  */
 static inline int g_26_3( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_26 *his_data, *ev_data = (_msg_t_26 *) event_data;
	 his_data = (_msg_t_26 *)fsm_get_history( fsm, 1);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_dst == NULL )) return 0;
	 const char *ip_dst_1 =  his_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( his_data->ip_proto_id == NULL )) return 0;
	 double ip_proto_id_1 = *( his_data->ip_proto_id );/* 61 */
	 if( unlikely( his_data->ip_proto_id == NULL )) return 0;
	 double ip_proto_id_2 = *( his_data->ip_proto_id );/* 61 */
	 if( unlikely( ev_data->ip_proto_id == NULL )) return 0;
	 double ip_proto_id = *( ev_data->ip_proto_id );/* 61 */
	 if( unlikely( his_data->ip_src == NULL )) return 0;
	 const char *ip_src_1 =  his_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return ((ip_proto_id != ip_proto_id_2) && ((ip_proto_id != ip_proto_id_1) && (0 == strcmp(ip_dst , ip_dst_1) && 0 == strcmp(ip_src , ip_src_1))));
 }
 
 /** 94
  * Rule 26, event 4
  * IP packet header with another eight-bit IP protocol field set (4)
  */
 static inline int g_26_4( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_26 *his_data, *ev_data = (_msg_t_26 *) event_data;
	 his_data = (_msg_t_26 *)fsm_get_history( fsm, 1);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_dst == NULL )) return 0;
	 const char *ip_dst_1 =  his_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( his_data->ip_proto_id == NULL )) return 0;
	 double ip_proto_id_1 = *( his_data->ip_proto_id );/* 61 */
	 if( unlikely( his_data->ip_proto_id == NULL )) return 0;
	 double ip_proto_id_3 = *( his_data->ip_proto_id );/* 61 */
	 if( unlikely( ev_data->ip_proto_id == NULL )) return 0;
	 double ip_proto_id = *( ev_data->ip_proto_id );/* 61 */
	 if( unlikely( his_data->ip_src == NULL )) return 0;
	 const char *ip_src_1 =  his_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;

	 return ((ip_proto_id != ip_proto_id_3) && ((ip_proto_id != ip_proto_id_1) && (0 == strcmp(ip_dst , ip_dst_1) && 0 == strcmp(ip_src , ip_src_1))));
 }
 
 /** 407
  * States of FSM for rule 26
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_26_0, s_26_1, s_26_2, s_26_3, s_26_4, s_26_5, s_26_6;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_26_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "Probable IP protocol scan (4 different attempts in a row on different protocols).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 IP packet header with the eight-bit IP protocol field set (1) */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_26_1, .action = 1, .target_state = &s_26_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_26_1 = {
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
  s_26_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_26_3 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_26_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 1000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_26_3}, //FSM_ACTION_DO_NOTHING
		 /** 456 IP packet header with another eight-bit IP protocol field set (2) */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_26_2, .action = 1, .target_state = &s_26_5}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 2
 },
 /** 427
  * root node
  */
  s_26_5 = {
	 .delay        = {.time_min = 1LL, .time_max = 1000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  = "Probable IP protocol scan (4 different attempts in a row on different protocols).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_26_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 IP packet header with another eight-bit IP protocol field set (3) */
		 /** 458 A real event */
		 { .event_type = 3, .guard = &g_26_3, .action = 1, .target_state = &s_26_6}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 2
 }, s_26_6 = {
	 .delay        = {.time_min = 1LL, .time_max = 1000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_26_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 IP packet header with another eight-bit IP protocol field set (4) */
		 /** 458 A real event */
		 { .event_type = 4, .guard = &g_26_4, .action = 0, .target_state = &s_26_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_26(){
		 return fsm_init( &s_26_0, &s_26_1, &s_26_2, &s_26_3, EVENTS_COUNT_26 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 27======================================
 #define EVENTS_COUNT_27 4

 #define PROTO_ATTS_COUNT_27 4

 /** 865
  * Proto_atts for rule 27
  */
 
 static proto_attribute_t proto_atts_27[ PROTO_ATTS_COUNT_27 ] = {{.proto = "ip", .proto_id = 178, .att = "dst", .att_id = 13, .data_type = 1}, {.proto = "ip", .proto_id = 178, .att = "proto_id", .att_id = 10, .data_type = 0}, {.proto = "ip", .proto_id = 178, .att = "src", .att_id = 12, .data_type = 1}, {.proto = "udp", .proto_id = 376, .att = "dest_port", .att_id = 2, .data_type = 0}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_27[ 5 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_27[ 0 ] ,  &proto_atts_27[ 1 ] ,  &proto_atts_27[ 2 ] ,  &proto_atts_27[ 3 ] }
	 },
	 {//event_2
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_27[ 0 ] ,  &proto_atts_27[ 1 ] ,  &proto_atts_27[ 2 ] ,  &proto_atts_27[ 3 ] }
	 },
	 {//event_3
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_27[ 0 ] ,  &proto_atts_27[ 1 ] ,  &proto_atts_27[ 2 ] ,  &proto_atts_27[ 3 ] }
	 },
	 {//event_4
		 .elements_count = 4,
		 .data = (void* []) { &proto_atts_27[ 0 ] ,  &proto_atts_27[ 1 ] ,  &proto_atts_27[ 2 ] ,  &proto_atts_27[ 3 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_27{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const char *ip_dst;
	 const double *ip_proto_id;
	 const char *ip_src;
	 const double *udp_dest_port;
 }_msg_t_27;
 /** 592
  * Create an instance of _msg_t_27
  */
 static inline _msg_t_27* _allocate_msg_t_27(){
	 _msg_t_27 *m = mmt_mem_alloc( sizeof( _msg_t_27 ));
	 m->ip_dst = NULL;
	 m->ip_proto_id = NULL;
	 m->ip_src = NULL;
	 m->udp_dest_port = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_27( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_27 *new_msg = _allocate_msg_t_27();
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
			 case 10:// attribute proto_id
				 new_msg->ip_proto_id = (double *) msg->elements[i].data;
				 break;
			 case 12:// attribute src
				 new_msg->ip_src = (char *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 633
			 break;
		 case 376:// protocol udp
			 switch( msg->elements[i].att_id ){
			 case 2:// attribute dest_port
				 new_msg->udp_dest_port = (double *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_27( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_27 ];
	 size_t i;	 _msg_t_27 *msg = (_msg_t_27 *) data;
	 for( i=0; i<EVENTS_COUNT_27; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->ip_dst != NULL && msg->ip_proto_id != NULL && msg->ip_src != NULL && msg->udp_dest_port != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->ip_dst != NULL && msg->ip_proto_id != NULL && msg->ip_src != NULL && msg->udp_dest_port != NULL )
		 hash_table[ 1 ] = 2;
	 if( msg->ip_dst != NULL && msg->ip_proto_id != NULL && msg->ip_src != NULL && msg->udp_dest_port != NULL )
		 hash_table[ 2 ] = 3;
	 if( msg->ip_dst != NULL && msg->ip_proto_id != NULL && msg->ip_src != NULL && msg->udp_dest_port != NULL )
		 hash_table[ 3 ] = 4;
	 return hash_table;
 }
 /** 94
  * Rule 27, event 1
  * UDP packet header with a destination port field set (1)
  */
 static inline int g_27_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_27 *his_data, *ev_data = (_msg_t_27 *) event_data;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_proto_id == NULL )) return 0;
	 double ip_proto_id = *( ev_data->ip_proto_id );/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->udp_dest_port == NULL )) return 0;
	 double udp_dest_port = *( ev_data->udp_dest_port );

	 return ((ip_proto_id == 17) && ((udp_dest_port != 0) && 0 != strcmp(ip_src , ip_dst)));
 }
 
 /** 94
  * Rule 27, event 2
  * UDP packet header with another destination port field set (2)
  */
 static inline int g_27_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_27 *his_data, *ev_data = (_msg_t_27 *) event_data;
	 his_data = (_msg_t_27 *)fsm_get_history( fsm, 1);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_dst == NULL )) return 0;
	 const char *ip_dst_1 =  his_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_proto_id == NULL )) return 0;
	 double ip_proto_id = *( ev_data->ip_proto_id );/* 61 */
	 if( unlikely( his_data->ip_src == NULL )) return 0;
	 const char *ip_src_1 =  his_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;/* 61 */
	 if( unlikely( his_data->udp_dest_port == NULL )) return 0;
	 double udp_dest_port_1 = *( his_data->udp_dest_port );/* 61 */
	 if( unlikely( ev_data->udp_dest_port == NULL )) return 0;
	 double udp_dest_port = *( ev_data->udp_dest_port );

	 return ((ip_proto_id == 17) && ((udp_dest_port != udp_dest_port_1) && (0 == strcmp(ip_dst , ip_dst_1) && 0 == strcmp(ip_src , ip_src_1))));
 }
 
 /** 94
  * Rule 27, event 3
  * UDP packet header with another destination port field set (3)
  */
 static inline int g_27_3( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_27 *his_data, *ev_data = (_msg_t_27 *) event_data;
	 his_data = (_msg_t_27 *)fsm_get_history( fsm, 1);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_dst == NULL )) return 0;
	 const char *ip_dst_1 =  his_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_proto_id == NULL )) return 0;
	 double ip_proto_id = *( ev_data->ip_proto_id );/* 61 */
	 if( unlikely( his_data->ip_src == NULL )) return 0;
	 const char *ip_src_1 =  his_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;/* 61 */
	 if( unlikely( his_data->udp_dest_port == NULL )) return 0;
	 double udp_dest_port_1 = *( his_data->udp_dest_port );/* 61 */
	 if( unlikely( his_data->udp_dest_port == NULL )) return 0;
	 double udp_dest_port_2 = *( his_data->udp_dest_port );/* 61 */
	 if( unlikely( ev_data->udp_dest_port == NULL )) return 0;
	 double udp_dest_port = *( ev_data->udp_dest_port );

	 return ((ip_proto_id == 17) && ((udp_dest_port != udp_dest_port_2) && ((udp_dest_port != udp_dest_port_1) && (0 == strcmp(ip_dst , ip_dst_1) && 0 == strcmp(ip_src , ip_src_1)))));
 }
 
 /** 94
  * Rule 27, event 4
  * UDP packet header with another destination port field set (4)
  */
 static inline int g_27_4( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_27 *his_data, *ev_data = (_msg_t_27 *) event_data;
	 his_data = (_msg_t_27 *)fsm_get_history( fsm, 1);
	 if( unlikely( his_data == NULL )) return 0;/* 61 */
	 if( unlikely( his_data->ip_dst == NULL )) return 0;
	 const char *ip_dst_1 =  his_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_dst == NULL )) return 0;
	 const char *ip_dst =  ev_data->ip_dst ;/* 61 */
	 if( unlikely( ev_data->ip_proto_id == NULL )) return 0;
	 double ip_proto_id = *( ev_data->ip_proto_id );/* 61 */
	 if( unlikely( his_data->ip_src == NULL )) return 0;
	 const char *ip_src_1 =  his_data->ip_src ;/* 61 */
	 if( unlikely( ev_data->ip_src == NULL )) return 0;
	 const char *ip_src =  ev_data->ip_src ;/* 61 */
	 if( unlikely( his_data->udp_dest_port == NULL )) return 0;
	 double udp_dest_port_1 = *( his_data->udp_dest_port );/* 61 */
	 if( unlikely( his_data->udp_dest_port == NULL )) return 0;
	 double udp_dest_port_3 = *( his_data->udp_dest_port );/* 61 */
	 if( unlikely( ev_data->udp_dest_port == NULL )) return 0;
	 double udp_dest_port = *( ev_data->udp_dest_port );

	 return ((ip_proto_id == 17) && ((udp_dest_port != udp_dest_port_3) && ((udp_dest_port != udp_dest_port_1) && (0 == strcmp(ip_dst , ip_dst_1) && 0 == strcmp(ip_src , ip_src_1)))));
 }
 
 /** 407
  * States of FSM for rule 27
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_27_0, s_27_1, s_27_2, s_27_3, s_27_4, s_27_5, s_27_6;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_27_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "Probable UDP protocol scan (4 different attempts in a row on different ports).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 UDP packet header with a destination port field set (1) */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_27_1, .action = 1, .target_state = &s_27_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_27_1 = {
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
  s_27_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_27_3 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_27_4 = {
	 .delay        = {.time_min = 1LL, .time_max = 1000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_27_3}, //FSM_ACTION_DO_NOTHING
		 /** 456 UDP packet header with another destination port field set (2) */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_27_2, .action = 1, .target_state = &s_27_5}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 2
 },
 /** 427
  * root node
  */
  s_27_5 = {
	 .delay        = {.time_min = 1LL, .time_max = 1000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  = "Probable UDP protocol scan (4 different attempts in a row on different ports).",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_27_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 UDP packet header with another destination port field set (3) */
		 /** 458 A real event */
		 { .event_type = 3, .guard = &g_27_3, .action = 1, .target_state = &s_27_6}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 2
 }, s_27_6 = {
	 .delay        = {.time_min = 1LL, .time_max = 1000000LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 0,
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_27_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 UDP packet header with another destination port field set (4) */
		 /** 458 A real event */
		 { .event_type = 4, .guard = &g_27_4, .action = 0, .target_state = &s_27_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_27(){
		 return fsm_init( &s_27_0, &s_27_1, &s_27_2, &s_27_3, EVENTS_COUNT_27 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================RULE 28======================================
 #define EVENTS_COUNT_28 2

 #define PROTO_ATTS_COUNT_28 3

 /** 865
  * Proto_atts for rule 28
  */
 
 static proto_attribute_t proto_atts_28[ PROTO_ATTS_COUNT_28 ] = {{.proto = "tcp", .proto_id = 354, .att = "fin", .att_id = 7, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "psh", .att_id = 10, .data_type = 0}, {.proto = "tcp", .proto_id = 354, .att = "urg", .att_id = 12, .data_type = 0}};
 /** 877
  * Detail of proto_atts for each event
  */
 
 static mmt_array_t proto_atts_events_28[ 3 ] = { {.elements_count = 0, .data = NULL}, 
	 {//event_1
		 .elements_count = 1,
		 .data = (void* []) { &proto_atts_28[ 2 ] }
	 },
	 {//event_2
		 .elements_count = 2,
		 .data = (void* []) { &proto_atts_28[ 0 ] ,  &proto_atts_28[ 1 ] }
	 } 
 };//end proto_atts_events_

 /** 556
  * Structure to represent event data
  */
 typedef struct _msg_struct_28{
	 uint64_t timestamp;//timestamp
	 uint64_t counter;//index of packet
	 const double *tcp_fin;
	 const double *tcp_psh;
	 const double *tcp_urg;
 }_msg_t_28;
 /** 592
  * Create an instance of _msg_t_28
  */
 static inline _msg_t_28* _allocate_msg_t_28(){
	 _msg_t_28 *m = mmt_mem_alloc( sizeof( _msg_t_28 ));
	 m->tcp_fin = NULL;
	 m->tcp_psh = NULL;
	 m->tcp_urg = NULL;
	 m->timestamp = 0;//timestamp
	 m->counter   = 0;//index of packet
	 return m; 
 }
 /** 616
  * Public API
  */
 static void *convert_message_to_event_28( const message_t *msg){
	 if( unlikely( msg == NULL )) return NULL;
	 _msg_t_28 *new_msg = _allocate_msg_t_28();
	 size_t i;
	 new_msg->timestamp = msg->timestamp;
	 new_msg->counter = msg->counter;
	 for( i=0; i<msg->elements_count; i++){
		 switch( msg->elements[i].proto_id ){/** 626 For each protocol*/
		 case 354:// protocol tcp
			 switch( msg->elements[i].att_id ){
			 case 7:// attribute fin
				 new_msg->tcp_fin = (double *) msg->elements[i].data;
				 break;
			 case 10:// attribute psh
				 new_msg->tcp_psh = (double *) msg->elements[i].data;
				 break;
			 case 12:// attribute urg
				 new_msg->tcp_urg = (double *) msg->elements[i].data;
				 break;
			 }//end switch of att_id 650
		 }//end switch
	 }//end for
	 return (void *)new_msg; //653
 }//end function
 /** 518
  * Public API
  */
 static const uint16_t* hash_message_28( const void *data ){
	 static uint16_t hash_table[ EVENTS_COUNT_28 ];
	 size_t i;	 _msg_t_28 *msg = (_msg_t_28 *) data;
	 for( i=0; i<EVENTS_COUNT_28; i++) hash_table[i] = 0;/** 524 Rest hash_table. This is call for every executions*/
	 //if( msg == NULL ) return hash_table;

	 if( msg->tcp_urg != NULL )
		 hash_table[ 0 ] = 1;
	 if( msg->tcp_fin != NULL && msg->tcp_psh != NULL )
		 hash_table[ 1 ] = 2;
	 return hash_table;
 }
 /** 94
  * Rule 28, event 1
  * TCP packet with flag FIN active
  */
 static inline int g_28_1( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_28 *his_data, *ev_data = (_msg_t_28 *) event_data;/* 61 */
	 if( unlikely( ev_data->tcp_urg == NULL )) return 0;
	 double tcp_urg = *( ev_data->tcp_urg );

	 return (tcp_urg == 1);
 }
 
 /** 94
  * Rule 28, event 2
  * TCP packet with flags URG and PSH active
  */
 static inline int g_28_2( const void *event_data, const fsm_t *fsm ){
	 if( unlikely( event_data == NULL )) return 0;
	 const _msg_t_28 *his_data, *ev_data = (_msg_t_28 *) event_data;/* 61 */
	 if( unlikely( ev_data->tcp_fin == NULL )) return 0;
	 double tcp_fin = *( ev_data->tcp_fin );/* 61 */
	 if( unlikely( ev_data->tcp_psh == NULL )) return 0;
	 double tcp_psh = *( ev_data->tcp_psh );

	 return ((tcp_fin == 1) && (tcp_psh == 1));
 }
 
 /** 407
  * States of FSM for rule 28
  */
 
 /** 408
  * Predefine list of states: init, fail, pass, ...
  */
 static fsm_state_t s_28_0, s_28_1, s_28_2, s_28_3, s_28_4;
 /** 421
  * Initialize states: init, error, final, ...
  */
 static fsm_state_t
 /** 427
  * initial state
  */
  s_28_0 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  = "XMAS scan : TCP with all flags FIN, URG, PSH active.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 1, //FSM_ACTION_CREATE_INSTANCE
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 456 TCP packet with flag FIN active */
		 /** 458 A real event */
		 { .event_type = 1, .guard = &g_28_1, .action = 1, .target_state = &s_28_4}  //FSM_ACTION_CREATE_INSTANCE
	 },
	 .transitions_count = 1
 },
 /** 427
  * timeout/error state
  */
  s_28_1 = {
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
  s_28_2 = {
	 .delay        = {.time_min = 0, .time_max = 0, .counter_min = 0, .counter_max = 0},
	 .is_temporary = 0,//init or final states
	 .description  =  NULL ,
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = NULL,
	 .transitions_count = 0
 }, s_28_3 = {
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
  * root node
  */
  s_28_4 = {
	 .delay        = {.time_min = 0LL, .time_max = 0LL, .counter_min = 0LL, .counter_max = 0LL},
	 .is_temporary = 1,
	 .description  = "XMAS scan : TCP with all flags FIN, URG, PSH active.",
	 .entry_action = 0, //FSM_ACTION_DO_NOTHING
	 .exit_action  = 0, //FSM_ACTION_DO_NOTHING
	 .data         = NULL,
	 .transitions  = (fsm_transition_t[]){
		 /** 458 Timeout event will fire this transition */
		 { .event_type = 0, .guard = NULL  , .action = 0, .target_state = &s_28_1}, //FSM_ACTION_DO_NOTHING
		 /** 456 TCP packet with flags URG and PSH active */
		 /** 458 A real event */
		 { .event_type = 2, .guard = &g_28_2, .action = 0, .target_state = &s_28_2}  //FSM_ACTION_DO_NOTHING
	 },
	 .transitions_count = 2
 };
 /** 485
  * Create a new FSM for this rule
  */
 static void *create_new_fsm_28(){
		 return fsm_init( &s_28_0, &s_28_1, &s_28_2, &s_28_3, EVENTS_COUNT_28 );//init, error, final, inconclusive, events_count
 }//end function

 //======================================GENERAL======================================
 /** 666
  * Information of 26 rules
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
			 .proto_atts_events= proto_atts_events_1,
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
			 .proto_atts_events= proto_atts_events_2,
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
			 .proto_atts_events= proto_atts_events_3,
			 .description      = "TCP SYN requests on microsoft-ds port 445 with SYN ACK.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_3,
			 .hash_message     = &hash_message_3,
			 .convert_message  = &convert_message_to_event_3
		 },
		 {
			 .id               = 6,
			 .type_id          = 2,
			 .type_string      = "evasion",
			 .events_count     = EVENTS_COUNT_6,
			 .proto_atts_count = PROTO_ATTS_COUNT_6,
			 .proto_atts       = proto_atts_6,
			 .proto_atts_events= proto_atts_events_6,
			 .description      = "4_Analyse_03b : SYN and ACK paquets with a 0xC123D delta between TCP sequence numbers (scan done by SYNFUL attack).",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_6,
			 .hash_message     = &hash_message_6,
			 .convert_message  = &convert_message_to_event_6
		 },
		 {
			 .id               = 7,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_7,
			 .proto_atts_count = PROTO_ATTS_COUNT_7,
			 .proto_atts       = proto_atts_7,
			 .proto_atts_events= proto_atts_events_7,
			 .description      = "R4_Decod_1a : TCP RST is invalid if there is no corresponding TCP ACK (tcp.flags == 16) before belonging to the same session containing correct seq_nb and ack_nb.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_7,
			 .hash_message     = &hash_message_7,
			 .convert_message  = &convert_message_to_event_7
		 },
		 {
			 .id               = 8,
			 .type_id          = 2,
			 .type_string      = "evasion",
			 .events_count     = EVENTS_COUNT_8,
			 .proto_atts_count = PROTO_ATTS_COUNT_8,
			 .proto_atts       = proto_atts_8,
			 .proto_atts_events= proto_atts_events_8,
			 .description      = "C4_Analyse_03g: The IP options field must be homogeneous in all IP fragments.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_8,
			 .hash_message     = &hash_message_8,
			 .convert_message  = &convert_message_to_event_8
		 },
		 {
			 .id               = 9,
			 .type_id          = 2,
			 .type_string      = "evasion",
			 .events_count     = EVENTS_COUNT_9,
			 .proto_atts_count = PROTO_ATTS_COUNT_9,
			 .proto_atts       = proto_atts_9,
			 .proto_atts_events= proto_atts_events_9,
			 .description      = "C4_Analyse_03h: The minimum size of an IP fragment is 28 bytes and for an IP fragment with offset 0 it is 40.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_9,
			 .hash_message     = &hash_message_9,
			 .convert_message  = &convert_message_to_event_9
		 },
		 {
			 .id               = 10,
			 .type_id          = 2,
			 .type_string      = "evasion",
			 .events_count     = EVENTS_COUNT_10,
			 .proto_atts_count = PROTO_ATTS_COUNT_10,
			 .proto_atts       = proto_atts_10,
			 .proto_atts_events= proto_atts_events_10,
			 .description      = "C4_Analyse_03f : HTTP using a port different from 80 and 8080.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_10,
			 .hash_message     = &hash_message_10,
			 .convert_message  = &convert_message_to_event_10
		 },
		 {
			 .id               = 11,
			 .type_id          = 2,
			 .type_string      = "evasion",
			 .events_count     = EVENTS_COUNT_11,
			 .proto_atts_count = PROTO_ATTS_COUNT_11,
			 .proto_atts       = proto_atts_11,
			 .proto_atts_events= proto_atts_events_11,
			 .description      = "C4_Analyse_03h: IP packet size and eth payload size not coherent.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_11,
			 .hash_message     = &hash_message_11,
			 .convert_message  = &convert_message_to_event_11
		 },
		 {
			 .id               = 12,
			 .type_id          = 2,
			 .type_string      = "evasion",
			 .events_count     = EVENTS_COUNT_12,
			 .proto_atts_count = PROTO_ATTS_COUNT_12,
			 .proto_atts       = proto_atts_12,
			 .proto_atts_events= proto_atts_events_12,
			 .description      = "C4_Analyse_03c|d|e : HTTP packet URI contains non authorised characteres according to RFC2396 and RFC2234 or possibly directory traversal attack.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_12,
			 .hash_message     = &hash_message_12,
			 .convert_message  = &convert_message_to_event_12
		 },
		 {
			 .id               = 13,
			 .type_id          = 2,
			 .type_string      = "evasion",
			 .events_count     = EVENTS_COUNT_13,
			 .proto_atts_count = PROTO_ATTS_COUNT_13,
			 .proto_atts       = proto_atts_13,
			 .proto_atts_events= proto_atts_events_13,
			 .description      = "C4_Analyse_3b : Data in SYN packet.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_13,
			 .hash_message     = &hash_message_13,
			 .convert_message  = &convert_message_to_event_13
		 },
		 {
			 .id               = 14,
			 .type_id          = 2,
			 .type_string      = "evasion",
			 .events_count     = EVENTS_COUNT_14,
			 .proto_atts_count = PROTO_ATTS_COUNT_14,
			 .proto_atts       = proto_atts_14,
			 .proto_atts_events= proto_atts_events_14,
			 .description      = "C4_Analyse_3f bis: Unauthorized port number.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_14,
			 .hash_message     = &hash_message_14,
			 .convert_message  = &convert_message_to_event_14
		 },
		 {
			 .id               = 15,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_15,
			 .proto_atts_count = PROTO_ATTS_COUNT_15,
			 .proto_atts       = proto_atts_15,
			 .proto_atts_events= proto_atts_events_15,
			 .description      = "Nikto detection",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_15,
			 .hash_message     = &hash_message_15,
			 .convert_message  = &convert_message_to_event_15
		 },
		 {
			 .id               = 16,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_16,
			 .proto_atts_count = PROTO_ATTS_COUNT_16,
			 .proto_atts       = proto_atts_16,
			 .proto_atts_events= proto_atts_events_16,
			 .description      = "Two successive TCP SYN requests but with different destination addresses.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_16,
			 .hash_message     = &hash_message_16,
			 .convert_message  = &convert_message_to_event_16
		 },
		 {
			 .id               = 17,
			 .type_id          = 1,
			 .type_string      = "security",
			 .events_count     = EVENTS_COUNT_17,
			 .proto_atts_count = PROTO_ATTS_COUNT_17,
			 .proto_atts       = proto_atts_17,
			 .proto_atts_events= proto_atts_events_17,
			 .description      = "SMTP detected",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_17,
			 .hash_message     = &hash_message_17,
			 .convert_message  = &convert_message_to_event_17
		 },
		 {
			 .id               = 18,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_18,
			 .proto_atts_count = PROTO_ATTS_COUNT_18,
			 .proto_atts       = proto_atts_18,
			 .proto_atts_events= proto_atts_events_18,
			 .description      = "Invalid GRE version detected",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_18,
			 .hash_message     = &hash_message_18,
			 .convert_message  = &convert_message_to_event_18
		 },
		 {
			 .id               = 19,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_19,
			 .proto_atts_count = PROTO_ATTS_COUNT_19,
			 .proto_atts       = proto_atts_19,
			 .proto_atts_events= proto_atts_events_19,
			 .description      = "SQL Injection detected",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_19,
			 .hash_message     = &hash_message_19,
			 .convert_message  = &convert_message_to_event_19
		 },
		 {
			 .id               = 20,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_20,
			 .proto_atts_count = PROTO_ATTS_COUNT_20,
			 .proto_atts       = proto_atts_20,
			 .proto_atts_events= proto_atts_events_20,
			 .description      = "4 consecutive ICMP redirect packets. Possibly ICMP redirect flood.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_20,
			 .hash_message     = &hash_message_20,
			 .convert_message  = &convert_message_to_event_20
		 },
		 {
			 .id               = 21,
			 .type_id          = 2,
			 .type_string      = "evasion",
			 .events_count     = EVENTS_COUNT_21,
			 .proto_atts_count = PROTO_ATTS_COUNT_21,
			 .proto_atts       = proto_atts_21,
			 .proto_atts_events= proto_atts_events_21,
			 .description      = "IP fragmentation : fragments with offset always = 0 (allowed but could be an evasion).",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_21,
			 .hash_message     = &hash_message_21,
			 .convert_message  = &convert_message_to_event_21
		 },
		 {
			 .id               = 22,
			 .type_id          = 2,
			 .type_string      = "evasion",
			 .events_count     = EVENTS_COUNT_22,
			 .proto_atts_count = PROTO_ATTS_COUNT_22,
			 .proto_atts       = proto_atts_22,
			 .proto_atts_events= proto_atts_events_22,
			 .description      = "IP fragmentation : a fragment with a size less than 9 bytes (allowed but could be an evasion).",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_22,
			 .hash_message     = &hash_message_22,
			 .convert_message  = &convert_message_to_event_22
		 },
		 {
			 .id               = 23,
			 .type_id          = 2,
			 .type_string      = "evasion",
			 .events_count     = EVENTS_COUNT_23,
			 .proto_atts_count = PROTO_ATTS_COUNT_23,
			 .proto_atts       = proto_atts_23,
			 .proto_atts_events= proto_atts_events_23,
			 .description      = "Out of order IP fragmentation : a fragment with a size less than 9 bytes (allowed but could be an evasion).",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_23,
			 .hash_message     = &hash_message_23,
			 .convert_message  = &convert_message_to_event_23
		 },
		 {
			 .id               = 24,
			 .type_id          = 2,
			 .type_string      = "evasion",
			 .events_count     = EVENTS_COUNT_24,
			 .proto_atts_count = PROTO_ATTS_COUNT_24,
			 .proto_atts       = proto_atts_24,
			 .proto_atts_events= proto_atts_events_24,
			 .description      = "Overlapping IP fragmentation : difference in offset of concomitant fragments less than fragment length (allowed but could be an evasion).",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_24,
			 .hash_message     = &hash_message_24,
			 .convert_message  = &convert_message_to_event_24
		 },
		 {
			 .id               = 25,
			 .type_id          = 2,
			 .type_string      = "evasion",
			 .events_count     = EVENTS_COUNT_25,
			 .proto_atts_count = PROTO_ATTS_COUNT_25,
			 .proto_atts       = proto_atts_25,
			 .proto_atts_events= proto_atts_events_25,
			 .description      = "Overlapping unordered IP fragmentation : difference in offset of concomitant fragments less than fragment length (allowed but could be an evasion).",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_25,
			 .hash_message     = &hash_message_25,
			 .convert_message  = &convert_message_to_event_25
		 },
		 {
			 .id               = 26,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_26,
			 .proto_atts_count = PROTO_ATTS_COUNT_26,
			 .proto_atts       = proto_atts_26,
			 .proto_atts_events= proto_atts_events_26,
			 .description      = "Probable IP protocol scan (4 different attempts in a row on different protocols).",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_26,
			 .hash_message     = &hash_message_26,
			 .convert_message  = &convert_message_to_event_26
		 },
		 {
			 .id               = 27,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_27,
			 .proto_atts_count = PROTO_ATTS_COUNT_27,
			 .proto_atts       = proto_atts_27,
			 .proto_atts_events= proto_atts_events_27,
			 .description      = "Probable UDP protocol scan (4 different attempts in a row on different ports).",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_27,
			 .hash_message     = &hash_message_27,
			 .convert_message  = &convert_message_to_event_27
		 },
		 {
			 .id               = 28,
			 .type_id          = 0,
			 .type_string      = "attack",
			 .events_count     = EVENTS_COUNT_28,
			 .proto_atts_count = PROTO_ATTS_COUNT_28,
			 .proto_atts       = proto_atts_28,
			 .proto_atts_events= proto_atts_events_28,
			 .description      = "XMAS scan : TCP with all flags FIN, URG, PSH active.",
			 .if_satisfied     = NULL,
			 .if_not_satisfied = NULL,
			 .create_instance  = &create_new_fsm_28,
			 .hash_message     = &hash_message_28,
			 .convert_message  = &convert_message_to_event_28
		 }
	 };
	 *rules_arr = rules;
	 return 26;
 }
 /** 696
  * Moment the rules being encoded
  */
 
 const char * __get_generated_date(){ return "2016-12-21 18:13:11, version 1.0.0 (e9dc6f2)";};