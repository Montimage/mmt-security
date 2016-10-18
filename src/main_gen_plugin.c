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

int main( int argc, char** argv ){
	rule_t **rule_list;
	size_t rule_count, i;
	const char *tmp_code_file = "/tmp/fsm.c";

	mmt_assert( argc == 3, "Usage: %s lib_file.so property_file.xml", argv[0] );

	rule_count = read_rules_from_file( argv[2], &rule_list );

	generate_fsm( tmp_code_file, rule_list, rule_count );

	compile_gen_code(argv[1], tmp_code_file );

	mmt_info( "Encoded %zu rules from %s to %s", rule_count, argv[2], argv[1] );
	for( i=0; i<rule_count; i++ ){
		free_a_rule( rule_list[i], YES);
	}

	mmt_free( rule_list );
	return 0;
}
