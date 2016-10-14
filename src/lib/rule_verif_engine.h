/*
 * rule_verif_engine.h
 *
 *  Created on: Oct 14, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_LIB_RULE_VERIF_ENGINE_H_
#define SRC_LIB_RULE_VERIF_ENGINE_H_

#include "mmt_lib.h"
#include "plugin_header.h"

typedef void rule_engine_t;

//max number of events in a rule
//max number of instances of a rule at any moment
rule_engine_t* rule_engine_init( const rule_info_t *rule_info, size_t max_instances_count );

void rule_engine_process( rule_engine_t *engine, const message_t *message );

void rule_engine_free( rule_engine_t *engine );
#endif /* SRC_LIB_RULE_VERIF_ENGINE_H_ */
