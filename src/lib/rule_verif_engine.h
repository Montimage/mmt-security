/*
 * rule_verif_engine.h
 *
 *  Created on: Oct 14, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 *  Verify a rule.
 *  This manages: create/free all fsm instances of a rule.
 */

#ifndef SRC_LIB_RULE_VERIF_ENGINE_H_
#define SRC_LIB_RULE_VERIF_ENGINE_H_

#include "mmt_lib.h"
#include "plugin_header.h"
#include "mmt_security.h"

typedef void rule_engine_t;

//max number of events in a rule
//max number of instances of a rule at any moment
rule_engine_t* rule_engine_init( const rule_info_t *rule_info, size_t max_instances_count );

enum verdict_type rule_engine_process( rule_engine_t *engine, message_t *message );

void rule_engine_free( rule_engine_t *engine );

const mmt_array_t* rule_engine_get_valide_trace( const rule_engine_t *_engine );

#endif /* SRC_LIB_RULE_VERIF_ENGINE_H_ */
