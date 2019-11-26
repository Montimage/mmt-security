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
#endif /* SRC_LIB_PRE_EMBEDDED_FUNCTIONS_H_ */
