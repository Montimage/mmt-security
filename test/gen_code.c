/*
 * parse.c
 *
 *  Created on: 26 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include <string.h>
#include "../src/lib/base.h"
#include "../src/lib/expression.h"
#include "../src/lib/mmt_log.h"
#include "../src/lib/mmt_alloc.h"
#include "../src/lib/rule.h"
#include "../src/lib/gen_code.h"

int main(){
	rule_t **rule_list;
	size_t rule_count, i;
	rule_count = read_rules_from_file("test/xml/properties_acdc.xml", &rule_list );
	mmt_debug( "number of rules: %zu", rule_count );

	generate_fsm( "/tmp/fsm.c", rule_list, rule_count );

	for( i=0; i<rule_count; i++ ){
		free_a_rule( rule_list[i], YES);
	}
	mmt_free_and_assign_to_null( rule_list );
	return 0;
}
