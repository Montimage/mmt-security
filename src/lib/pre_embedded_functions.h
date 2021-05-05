/*
 * pre_embedded_functions.h
 *
 *  Created on: Apr 18, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@me.com>
 */

#ifndef SRC_LIB_PRE_EMBEDDED_FUNCTIONS_H_
#define SRC_LIB_PRE_EMBEDDED_FUNCTIONS_H_

#include "mmt_lib.h"
#include "mmt_security.h"

/**
 * The function checks if a proto.att exists or not.
 *
 * This function will cause MMT-Security to exclude proto_att from its mask, i.e.,
 * proto_att will be not checked its present in message_t.
 * The verification of the rule event containing this function will be done even
 * proto_att is NULL
 *
 * @return
 * 	- 1 if proto_att exists
 * 	- 0 if proto_att does not exist
 */
#define is_exist( x ) (x != 0)

/**
 * The function checks if a proto.att exists or not.
 *
 * This function does not exclude #proto_att from masks.
 * Consequently, when its is called from a boolean expression, it will always return false.
 *
 * @param proto_att
 * @return
 */
static inline int is_null( const void *proto_att ){
	mmt_debug( "is_null: %d", proto_att == NULL );
	return proto_att == NULL;
}

static inline int is_empty( const void *proto_att ){
	return (proto_att == NULL || ((char *)proto_att)[0] == '\0' );
}


/**
 * Get data value in
 * @param proto_id
 * @param att_id
 * @param event_id
 * @param trace
 */
static inline const void* get_value_from_trace(uint32_t proto_id, uint32_t att_id, int event_id,
		const mmt_array_t *const trace) {
	const message_t *msg;
	const message_element_t *me;
	uint64_t value = 0;
	int j;
	if( event_id >= trace->elements_count )
		return NULL;
	msg = trace->data[event_id];
	if( !msg )
		return NULL;
	for (j = 0; j < msg->elements_count; j++) {
		me = &msg->elements[j];
		if (me && me->proto_id == proto_id && me->att_id == att_id)
			return me->data;
	}
	return NULL;
}

static inline uint64_t get_numeric_value(uint32_t proto_id, uint32_t att_id, int event_id, const mmt_array_t *const trace ){
	const double *val = get_value_from_trace( proto_id, att_id, event_id, trace );
	if( val == NULL )
		return 0;
	else
		return (uint64_t) (*val);
}


/**The following functions are used for FORWARD packets**/
//drop packet: This function will be used by #drop
extern void mmt_probe_do_not_forward_packet(); //this function must be implemented inside mmt-probe
extern void mmt_probe_forward_packet(); //this function must be implemented inside mmt-probe
extern void mmt_probe_set_attribute_number_value(uint32_t, uint32_t, uint64_t); //this function must be implemented inside mmt-probe
//alias
#define set_numeric_value mmt_probe_set_attribute_number_value
#define forward_packet mmt_probe_forward_packet
/**
 * This function will be called by #update() if_satisfied function
 */
static inline void set_number_update( const proto_attribute_t *proto, double new_val ){
	mmt_probe_set_attribute_number_value( proto->proto_id, proto->att_id, new_val);
}

/**
 * This is default if_satisfied function in FORWARD rules when if_satisfied is not defined
 * It format is mmt_sec_handler_t
 */
static inline void forward_packet_if_satisfied( const rule_info_t *rule, int verdict, uint64_t timestamp,
		uint64_t counter, const mmt_array_t * const trace ){
	mmt_probe_forward_packet();
}


#endif /* SRC_LIB_PRE_EMBEDDED_FUNCTIONS_H_ */
