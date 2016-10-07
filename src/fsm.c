
/** 455
 * This file is generated automatically on 2016-10-06 18:23:24
 */
#include <string.h>
#include "base.h"
#include "mmt_fsm.h"

/** 274
 * ==================Rule 1====================
 * Several attempts to connect via ssh (brute force attack). Source address is either infected machine or attacker (no spoofing is possible).
 */

/** 77
 * Rule 1, event 1
 * SYN request
 */
static inline int g_1_1( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	double tcp_dest_port = ((report_t *)event->data)->tcp_dest_port;/* 54 */
	double tcp_flags = ((report_t *)event->data)->tcp_flags;

	return ((tcp_flags == 2) && (tcp_dest_port == 22));
}

/** 77
 * Rule 1, event 2
 * SYN ACK reply
 */
static inline int g_1_2( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	const char *ip_dst_1 = ((report_t *)fsm_get_history( fsm, 1 ))->ip_dst;/* 54 */
	const char *ip_dst = ((report_t *)event->data)->ip_dst;/* 54 */
	const char *ip_src_1 = ((report_t *)fsm_get_history( fsm, 1 ))->ip_src;/* 54 */
	const char *ip_src = ((report_t *)event->data)->ip_src;/* 54 */
	double tcp_flags = ((report_t *)event->data)->tcp_flags;/* 54 */
	double tcp_src_port = ((report_t *)event->data)->tcp_src_port;

	return ((tcp_flags == 18) && ((tcp_src_port == 22) && (0 == strcmp(ip_dst , ip_src_1) && 0 == strcmp(ip_src , ip_dst_1))));
}

/** 77
 * Rule 1, event 3
 * SYN request
 */
static inline int g_1_3( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	const char *ip_dst_1 = ((report_t *)fsm_get_history( fsm, 1 ))->ip_dst;/* 54 */
	const char *ip_dst = ((report_t *)event->data)->ip_dst;/* 54 */
	const char *ip_src_1 = ((report_t *)fsm_get_history( fsm, 1 ))->ip_src;/* 54 */
	const char *ip_src = ((report_t *)event->data)->ip_src;/* 54 */
	double tcp_dest_port = ((report_t *)event->data)->tcp_dest_port;/* 54 */
	double tcp_flags = ((report_t *)event->data)->tcp_flags;

	return ((tcp_flags == 2) && ((tcp_dest_port == 22) && (0 == strcmp(ip_src , ip_src_1) && 0 == strcmp(ip_dst , ip_dst_1))));
}

/** 77
 * Rule 1, event 4
 * SYN ACK reply
 */
static inline int g_1_4( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	const char *ip_dst_1 = ((report_t *)fsm_get_history( fsm, 1 ))->ip_dst;/* 54 */
	const char *ip_dst = ((report_t *)event->data)->ip_dst;/* 54 */
	const char *ip_src_1 = ((report_t *)fsm_get_history( fsm, 1 ))->ip_src;/* 54 */
	const char *ip_src = ((report_t *)event->data)->ip_src;/* 54 */
	double tcp_flags = ((report_t *)event->data)->tcp_flags;/* 54 */
	double tcp_src_port = ((report_t *)event->data)->tcp_src_port;

	return ((tcp_flags == 18) && ((tcp_src_port == 22) && (0 == strcmp(ip_dst , ip_src_1) && 0 == strcmp(ip_src , ip_dst_1))));
}

/** 286
 * States of FSM for rule 1
 */

/** 310
 * Predefine list of states: init, error, final, ...
 */
static fsm_state_t s_1_0, s_1_1, s_1_2, s_1_3, s_1_4;
/** 323
 * Initialize states: init, error, final, ...
 */
static fsm_state_t
/** 329
 * initial state
 */
 s_1_0 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = "Several attempts to connect via ssh (brute force attack). Source address is either infected machine or attacker (no spoofing is possible).",
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		/** 365 SYN request */
		{ EVENT  , NULL, &g_1_1, NULL, &s_1_3},
		/** 365 SYN ACK reply */
		{ EVENT  , NULL, &g_1_2, NULL, &s_1_3} 
	},
	.transitions_count = 2
},
/** 329
 * timeout/error state
 */
 s_1_1 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = NULL,
	.transitions_count = 0
},
/** 329
 * final state
 */
 s_1_2 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = NULL,
	.transitions_count = 0
},
/** 329
 * root node
 */
 s_1_3 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = (fsm_delay_t *){.time_min = 0.00, .time_max = 1.00, .counter_min = 0, .counter_max = 0},
	.description  = "Several attempts to connect via ssh (brute force attack). Source address is either infected machine or attacker (no spoofing is possible).",
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		{ TIMEOUT, NULL, NULL  , NULL, &s_1_2},
		/** 365 SYN request */
		{ EVENT  , NULL, &g_1_3, NULL, &s_1_4} 
	},
	.transitions_count = 2
}, s_1_4 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = (fsm_delay_t *){.time_min = 0.00, .time_max = 1.00, .counter_min = 0, .counter_max = 0},
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		{ TIMEOUT, NULL, NULL  , NULL, &s_1_1},
		/** 365 SYN ACK reply */
		{ EVENT  , NULL, &g_1_4, NULL, &s_1_2} 
	},
	.transitions_count = 2
};
/** 384
 * Create a new FSM
 */
inline fsm_t * new_fsm_1(){ return fsm_init( &s_1_0, &s_1_1 );}

/** 274
 * ==================Rule 2====================
 * Attempted to connect via ssh but reseted immediately. Source address is either infected machine or attacker (no spoofing is possible).
 */

/** 77
 * Rule 2, event 5
 * SYN request
 */
static inline int g_2_5( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	double tcp_dest_port = ((report_t *)event->data)->tcp_dest_port;/* 54 */
	double tcp_flags = ((report_t *)event->data)->tcp_flags;

	return ((tcp_flags == 2) && (tcp_dest_port == 22));
}

/** 77
 * Rule 2, event 6
 * SYN ACK reply
 */
static inline int g_2_6( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	const char *ip_dst_5 = ((report_t *)fsm_get_history( fsm, 5 ))->ip_dst;/* 54 */
	const char *ip_dst = ((report_t *)event->data)->ip_dst;/* 54 */
	const char *ip_src_5 = ((report_t *)fsm_get_history( fsm, 5 ))->ip_src;/* 54 */
	const char *ip_src = ((report_t *)event->data)->ip_src;/* 54 */
	double tcp_flags = ((report_t *)event->data)->tcp_flags;/* 54 */
	double tcp_src_port = ((report_t *)event->data)->tcp_src_port;

	return ((tcp_flags == 18) && ((tcp_src_port == 22) && (0 == strcmp(ip_dst , ip_src_5) && 0 == strcmp(ip_src , ip_dst_5))));
}

/** 77
 * Rule 2, event 7
 * RST reset
 */
static inline int g_2_7( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	const char *ip_dst_5 = ((report_t *)fsm_get_history( fsm, 5 ))->ip_dst;/* 54 */
	const char *ip_dst = ((report_t *)event->data)->ip_dst;/* 54 */
	const char *ip_src_5 = ((report_t *)fsm_get_history( fsm, 5 ))->ip_src;/* 54 */
	const char *ip_src = ((report_t *)event->data)->ip_src;/* 54 */
	double tcp_dest_port = ((report_t *)event->data)->tcp_dest_port;/* 54 */
	double tcp_flags = ((report_t *)event->data)->tcp_flags;

	return ((tcp_flags == 4) && ((tcp_dest_port == 22) && (0 == strcmp(ip_dst , ip_dst_5) && 0 == strcmp(ip_src , ip_src_5))));
}

/** 286
 * States of FSM for rule 2
 */

/** 310
 * Predefine list of states: init, error, final, ...
 */
static fsm_state_t s_2_0, s_2_1, s_2_2, s_2_3, s_2_4, s_2_5;
/** 323
 * Initialize states: init, error, final, ...
 */
static fsm_state_t
/** 329
 * initial state
 */
 s_2_0 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = "Attempted to connect via ssh but reseted immediately. Source address is either infected machine or attacker (no spoofing is possible).",
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		/** 365 SYN request */
		{ EVENT  , NULL, &g_2_5, NULL, &s_2_3},
		/** 365 SYN ACK reply */
		{ EVENT  , NULL, &g_2_6, NULL, &s_2_4} 
	},
	.transitions_count = 2
},
/** 329
 * timeout/error state
 */
 s_2_1 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = NULL,
	.transitions_count = 0
},
/** 329
 * final state
 */
 s_2_2 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = NULL,
	.transitions_count = 0
}, s_2_3 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = (fsm_delay_t *){.time_min = 0.00, .time_max = 1.00, .counter_min = 0, .counter_max = 0},
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		{ TIMEOUT, NULL, NULL  , NULL, &s_2_5},
		/** 365 SYN ACK reply */
		{ EVENT  , NULL, &g_2_6, NULL, &s_2_5} 
	},
	.transitions_count = 2
}, s_2_4 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = (fsm_delay_t *){.time_min = 0.00, .time_max = 1.00, .counter_min = 0, .counter_max = 0},
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		{ TIMEOUT, NULL, NULL  , NULL, &s_2_5},
		/** 365 SYN request */
		{ EVENT  , NULL, &g_2_5, NULL, &s_2_5} 
	},
	.transitions_count = 2
},
/** 329
 * root node
 */
 s_2_5 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = (fsm_delay_t *){.time_min = 0.00, .time_max = 244.00, .counter_min = 0, .counter_max = 0},
	.description  = "Attempted to connect via ssh but reseted immediately. Source address is either infected machine or attacker (no spoofing is possible).",
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		{ TIMEOUT, NULL, NULL  , NULL, &s_2_2},
		/** 365 RST reset */
		{ EVENT  , NULL, &g_2_7, NULL, &s_2_2} 
	},
	.transitions_count = 2
};
/** 384
 * Create a new FSM
 */
inline fsm_t * new_fsm_2(){ return fsm_init( &s_2_0, &s_2_1 );}

/** 274
 * ==================Rule 3====================
 * TCP SYN requests on microsoft-ds port 445 with SYN ACK.
 */

/** 77
 * Rule 3, event 8
 * SYN request
 */
static inline int g_3_8( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	double tcp_dest_port = ((report_t *)event->data)->tcp_dest_port;/* 54 */
	double tcp_flags = ((report_t *)event->data)->tcp_flags;

	return ((tcp_flags == 2) && (tcp_dest_port == 445));
}

/** 77
 * Rule 3, event 9
 * SYN ACK reply
 */
static inline int g_3_9( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	const char *ip_dst_8 = ((report_t *)fsm_get_history( fsm, 8 ))->ip_dst;/* 54 */
	const char *ip_src = ((report_t *)event->data)->ip_src;/* 54 */
	double tcp_flags = ((report_t *)event->data)->tcp_flags;

	return ((tcp_flags == 18) && 0 == strcmp(ip_src , ip_dst_8));
}

/** 286
 * States of FSM for rule 3
 */

/** 310
 * Predefine list of states: init, error, final, ...
 */
static fsm_state_t s_3_0, s_3_1, s_3_2, s_3_3;
/** 323
 * Initialize states: init, error, final, ...
 */
static fsm_state_t
/** 329
 * initial state
 */
 s_3_0 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = "TCP SYN requests on microsoft-ds port 445 with SYN ACK.",
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		/** 365 SYN request */
		{ EVENT  , NULL, &g_3_8, NULL, &s_3_3} 
	},
	.transitions_count = 1
},
/** 329
 * timeout/error state
 */
 s_3_1 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = NULL,
	.transitions_count = 0
},
/** 329
 * final state
 */
 s_3_2 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = NULL,
	.transitions_count = 0
},
/** 329
 * root node
 */
 s_3_3 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = (fsm_delay_t *){.time_min = 0.00, .time_max = 6.00, .counter_min = 0, .counter_max = 0},
	.description  = "TCP SYN requests on microsoft-ds port 445 with SYN ACK.",
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		{ TIMEOUT, NULL, NULL  , NULL, &s_3_2},
		/** 365 SYN ACK reply */
		{ EVENT  , NULL, &g_3_9, NULL, &s_3_2} 
	},
	.transitions_count = 2
};
/** 384
 * Create a new FSM
 */
inline fsm_t * new_fsm_3(){ return fsm_init( &s_3_0, &s_3_1 );}

/** 274
 * ==================Rule 4====================
 * Two successive TCP SYN requests but with different destnation addresses.
 */

/** 77
 * Rule 4, event 12
 * SYN request
 */
static inline int g_4_12( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	double tcp_flags = ((report_t *)event->data)->tcp_flags;

	return (tcp_flags == 2);
}

/** 77
 * Rule 4, event 13
 * SYN request
 */
static inline int g_4_13( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	const char *ip_dst_12 = ((report_t *)fsm_get_history( fsm, 12 ))->ip_dst;/* 54 */
	const char *ip_dst = ((report_t *)event->data)->ip_dst;/* 54 */
	const char *ip_src_12 = ((report_t *)fsm_get_history( fsm, 12 ))->ip_src;/* 54 */
	const char *ip_src = ((report_t *)event->data)->ip_src;/* 54 */
	double tcp_flags = ((report_t *)event->data)->tcp_flags;

	return ((tcp_flags == 2) && (0 != strcmp(ip_dst , ip_dst_12) && 0 == strcmp(ip_src , ip_src_12)));
}

/** 286
 * States of FSM for rule 4
 */

/** 310
 * Predefine list of states: init, error, final, ...
 */
static fsm_state_t s_4_0, s_4_1, s_4_2, s_4_3;
/** 323
 * Initialize states: init, error, final, ...
 */
static fsm_state_t
/** 329
 * initial state
 */
 s_4_0 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = "Two successive TCP SYN requests but with different destnation addresses.",
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		/** 365 SYN request */
		{ EVENT  , NULL, &g_4_12, NULL, &s_4_3} 
	},
	.transitions_count = 1
},
/** 329
 * timeout/error state
 */
 s_4_1 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = NULL,
	.transitions_count = 0
},
/** 329
 * final state
 */
 s_4_2 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = NULL,
	.transitions_count = 0
},
/** 329
 * root node
 */
 s_4_3 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = (fsm_delay_t *){.time_min = 0.00, .time_max = 1.00, .counter_min = 0, .counter_max = 0},
	.description  = "Two successive TCP SYN requests but with different destnation addresses.",
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		{ TIMEOUT, NULL, NULL  , NULL, &s_4_2},
		/** 365 SYN request */
		{ EVENT  , NULL, &g_4_13, NULL, &s_4_2} 
	},
	.transitions_count = 2
};
/** 384
 * Create a new FSM
 */
inline fsm_t * new_fsm_4(){ return fsm_init( &s_4_0, &s_4_1 );}

/** 274
 * ==================Rule 5====================
 * TCP SYN requests with SYN ACK.
 */

/** 77
 * Rule 5, event 10
 * SYN request
 */
static inline int g_5_10( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	double tcp_flags = ((report_t *)event->data)->tcp_flags;

	return (tcp_flags == 2);
}

/** 77
 * Rule 5, event 11
 * SYN ACK replyyyyyy
 */
static inline int g_5_11( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	const char *ip_dst_10 = ((report_t *)fsm_get_history( fsm, 10 ))->ip_dst;/* 54 */
	const char *ip_src = ((report_t *)event->data)->ip_src;/* 54 */
	double tcp_flags = ((report_t *)event->data)->tcp_flags;

	return ((tcp_flags == 18) && 0 == strcmp(ip_src , ip_dst_10));
}

/** 286
 * States of FSM for rule 5
 */

/** 310
 * Predefine list of states: init, error, final, ...
 */
static fsm_state_t s_5_0, s_5_1, s_5_2, s_5_3;
/** 323
 * Initialize states: init, error, final, ...
 */
static fsm_state_t
/** 329
 * initial state
 */
 s_5_0 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = "TCP SYN requests with SYN ACK.",
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		/** 365 SYN request */
		{ EVENT  , NULL, &g_5_10, NULL, &s_5_3} 
	},
	.transitions_count = 1
},
/** 329
 * timeout/error state
 */
 s_5_1 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = NULL,
	.exit_action  = exec("py_createstix(4_TCP_SYN_request_without_SYN_ACK_could_be_a_spoofed_address, ip.src.10)"),
	.entry_action = NULL,
	.transitions  = NULL,
	.transitions_count = 0
},
/** 329
 * final state
 */
 s_5_2 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = NULL,
	.transitions_count = 0
},
/** 329
 * root node
 */
 s_5_3 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = (fsm_delay_t *){.time_min = 0.00, .time_max = 1.00, .counter_min = 0, .counter_max = 0},
	.description  = "TCP SYN requests with SYN ACK.",
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		{ TIMEOUT, NULL, NULL  , NULL, &s_5_2},
		/** 365 SYN ACK replyyyyyy */
		{ EVENT  , NULL, &g_5_11, NULL, &s_5_2} 
	},
	.transitions_count = 2
};
/** 384
 * Create a new FSM
 */
inline fsm_t * new_fsm_5(){ return fsm_init( &s_5_0, &s_5_1 );}

/** 274
 * ==================Rule 6====================
 * Get request from ghost
 */

/** 77
 * Rule 6, event 1
 * Having GET request
 */
static inline int g_6_1( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	const char *http_method = ((report_t *)event->data)->http_method;

	return 0 == strcmp(http_method , "GET");
}

/** 77
 * Rule 6, event 2
 * Must have User-Agent
 */
static inline int g_6_2( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	const char *http_user_agent = ((report_t *)event->data)->http_user_agent;

	return 0 != strcmp(http_user_agent , "phantom");
}

/** 286
 * States of FSM for rule 6
 */

/** 310
 * Predefine list of states: init, error, final, ...
 */
static fsm_state_t s_6_0, s_6_1, s_6_2, s_6_3;
/** 323
 * Initialize states: init, error, final, ...
 */
static fsm_state_t
/** 329
 * initial state
 */
 s_6_0 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = "Get request from ghost",
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		/** 365 Having GET request */
		{ EVENT  , NULL, &g_6_1, NULL, &s_6_3} 
	},
	.transitions_count = 1
},
/** 329
 * timeout/error state
 */
 s_6_1 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = NULL,
	.transitions_count = 0
},
/** 329
 * final state
 */
 s_6_2 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = NULL,
	.transitions_count = 0
},
/** 329
 * root node
 */
 s_6_3 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = (fsm_delay_t *){.time_min = 0.00, .time_max = 1.00, .counter_min = 0, .counter_max = 0},
	.description  = "Get request from ghost",
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		{ TIMEOUT, NULL, NULL  , NULL, &s_6_2},
		/** 365 Must have User-Agent */
		{ EVENT  , NULL, &g_6_2, NULL, &s_6_2} 
	},
	.transitions_count = 2
};
/** 384
 * Create a new FSM
 */
inline fsm_t * new_fsm_6(){ return fsm_init( &s_6_0, &s_6_1 );}

/** 274
 * ==================Rule 8====================
 * IPv4 address conflict detection (RFC5227). Possible arp poisoning.
 */

/** 77
 * Rule 8, event 1
 * An arp who was requested
 */
static inline int g_8_1( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	double arp_ar_op = ((report_t *)event->data)->arp_ar_op;

	return (arp_ar_op == 1);
}

/** 77
 * Rule 8, event 2
 * An arp reply with MAC address
 */
static inline int g_8_2( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	double arp_ar_op = ((report_t *)event->data)->arp_ar_op;/* 54 */
	const char *arp_ar_sip = ((report_t *)event->data)->arp_ar_sip;/* 54 */
	const char *arp_ar_tip_1 = ((report_t *)fsm_get_history( fsm, 1 ))->arp_ar_tip;

	return ((arp_ar_op == 2) && 0 == strcmp(arp_ar_sip , arp_ar_tip_1));
}

/** 77
 * Rule 8, event 3
 * An arp reply but with different MAC address
 */
static inline int g_8_3( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	double arp_ar_op = ((report_t *)event->data)->arp_ar_op;/* 54 */
	const char *arp_ar_sha_2 = ((report_t *)fsm_get_history( fsm, 2 ))->arp_ar_sha;/* 54 */
	const char *arp_ar_sha = ((report_t *)event->data)->arp_ar_sha;/* 54 */
	const char *arp_ar_sip = ((report_t *)event->data)->arp_ar_sip;/* 54 */
	const char *arp_ar_tip_1 = ((report_t *)fsm_get_history( fsm, 1 ))->arp_ar_tip;

	return (((arp_ar_op == 2) && 0 == strcmp(arp_ar_sip , arp_ar_tip_1)) && 0 != strcmp(arp_ar_sha , arp_ar_sha_2));
}

/** 286
 * States of FSM for rule 8
 */

/** 310
 * Predefine list of states: init, error, final, ...
 */
static fsm_state_t s_8_0, s_8_1, s_8_2, s_8_3, s_8_4, s_8_5;
/** 323
 * Initialize states: init, error, final, ...
 */
static fsm_state_t
/** 329
 * initial state
 */
 s_8_0 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = "IPv4 address conflict detection (RFC5227). Possible arp poisoning.",
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		/** 365 An arp who was requested */
		{ EVENT  , NULL, &g_8_1, NULL, &s_8_3},
		/** 365 An arp reply with MAC address */
		{ EVENT  , NULL, &g_8_2, NULL, &s_8_4} 
	},
	.transitions_count = 2
},
/** 329
 * timeout/error state
 */
 s_8_1 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = NULL,
	.transitions_count = 0
},
/** 329
 * final state
 */
 s_8_2 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = NULL,
	.transitions_count = 0
}, s_8_3 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = (fsm_delay_t *){.time_min = 0.00, .time_max = 5.00, .counter_min = 0, .counter_max = 0},
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		{ TIMEOUT, NULL, NULL  , NULL, &s_8_5},
		/** 365 An arp reply with MAC address */
		{ EVENT  , NULL, &g_8_2, NULL, &s_8_5} 
	},
	.transitions_count = 2
}, s_8_4 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = (fsm_delay_t *){.time_min = 0.00, .time_max = 5.00, .counter_min = 0, .counter_max = 0},
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		{ TIMEOUT, NULL, NULL  , NULL, &s_8_5},
		/** 365 An arp who was requested */
		{ EVENT  , NULL, &g_8_1, NULL, &s_8_5} 
	},
	.transitions_count = 2
},
/** 329
 * root node
 */
 s_8_5 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = (fsm_delay_t *){.time_min = 0.00, .time_max = 5.00, .counter_min = 0, .counter_max = 0},
	.description  = "IPv4 address conflict detection (RFC5227). Possible arp poisoning.",
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		{ TIMEOUT, NULL, NULL  , NULL, &s_8_2},
		/** 365 An arp reply but with different MAC address */
		{ EVENT  , NULL, &g_8_3, NULL, &s_8_2} 
	},
	.transitions_count = 2
};
/** 384
 * Create a new FSM
 */
inline fsm_t * new_fsm_8(){ return fsm_init( &s_8_0, &s_8_1 );}

/** 274
 * ==================Rule 9====================
 * IPv4 address conflict detection (RFC5227). Possible arp poisoning.
 */

/** 77
 * Rule 9, event 4
 * An arp reply with MAC address
 */
static inline int g_9_4( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	double arp_ar_op = ((report_t *)event->data)->arp_ar_op;

	return (arp_ar_op == 2);
}

/** 77
 * Rule 9, event 5
 * An arp reply but with different MAC address
 */
static inline int g_9_5( void *condition, const fsm_event_t *event, const fsm_t *fsm ){/* 54 */
	double arp_ar_op = ((report_t *)event->data)->arp_ar_op;/* 54 */
	const char *arp_ar_sha_4 = ((report_t *)fsm_get_history( fsm, 4 ))->arp_ar_sha;/* 54 */
	const char *arp_ar_sha = ((report_t *)event->data)->arp_ar_sha;/* 54 */
	const char *arp_ar_sip_4 = ((report_t *)fsm_get_history( fsm, 4 ))->arp_ar_sip;/* 54 */
	const char *arp_ar_sip = ((report_t *)event->data)->arp_ar_sip;

	return (((arp_ar_op == 2) && 0 == strcmp(arp_ar_sip , arp_ar_sip_4)) && 0 != strcmp(arp_ar_sha , arp_ar_sha_4));
}

/** 286
 * States of FSM for rule 9
 */

/** 310
 * Predefine list of states: init, error, final, ...
 */
static fsm_state_t s_9_0, s_9_1, s_9_2, s_9_3;
/** 323
 * Initialize states: init, error, final, ...
 */
static fsm_state_t
/** 329
 * initial state
 */
 s_9_0 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = "IPv4 address conflict detection (RFC5227). Possible arp poisoning.",
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		/** 365 An arp reply with MAC address */
		{ EVENT  , NULL, &g_9_4, NULL, &s_9_3} 
	},
	.transitions_count = 1
},
/** 329
 * timeout/error state
 */
 s_9_1 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = NULL,
	.transitions_count = 0
},
/** 329
 * final state
 */
 s_9_2 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = NULL,
	.description  = NULL,
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = NULL,
	.transitions_count = 0
},
/** 329
 * root node
 */
 s_9_3 = {
	.timer        = 0,
	.counter      = 0,
	.delay        = (fsm_delay_t *){.time_min = 0.00, .time_max = 5.00, .counter_min = 0, .counter_max = 0},
	.description  = "IPv4 address conflict detection (RFC5227). Possible arp poisoning.",
	.exit_action  = NULL,
	.entry_action = NULL,
	.transitions  = (fsm_transition_t[]){
		{ TIMEOUT, NULL, NULL  , NULL, &s_9_2},
		/** 365 An arp reply but with different MAC address */
		{ EVENT  , NULL, &g_9_5, NULL, &s_9_2} 
	},
	.transitions_count = 2
};
/** 384
 * Create a new FSM
 */
inline fsm_t * new_fsm_9(){ return fsm_init( &s_9_0, &s_9_1 );}

/** 423
 * HASH
 */
inline uint16_t hash_proto_attribute( uint32_t proto_id, uint32_t att_id){
	switch( proto_id ){
/** 405
 * arp
 */
	case 30:
		switch ( att_id){
		case 5:	//ar_op
			return 0;
		case 6:	//ar_sha
			return 1;
		case 7:	//ar_sip
			return 2;
		case 9:	//ar_tip
			return 3;
		default:
			fprintf(stderr, "Do not find attribute %d of protocol 30 in the given rules.", att_id);
			exit(1);
		}//end att for 30
/** 405
 * http
 */
	case 153:
		switch ( att_id){
		case 1:	//method
			return 4;
		case 7:	//user_agent
			return 5;
		default:
			fprintf(stderr, "Do not find attribute %d of protocol 153 in the given rules.", att_id);
			exit(1);
		}//end att for 153
/** 405
 * ip
 */
	case 178:
		switch ( att_id){
		case 13:	//dst
			return 6;
		case 12:	//src
			return 7;
		default:
			fprintf(stderr, "Do not find attribute %d of protocol 178 in the given rules.", att_id);
			exit(1);
		}//end att for 178
/** 405
 * tcp
 */
	case 354:
		switch ( att_id){
		case 2:	//dest_port
			return 8;
		case 6:	//flags
			return 9;
		case 1:	//src_port
			return 10;
		default:
			fprintf(stderr, "Do not find attribute %d of protocol 354 in the given rules.", att_id);
			exit(1);
		}//last switch
	default:
		fprintf(stderr, "Do not find protocol %d in the given rules.", proto_id);
		exit(1);
	}
}