/*
 * main_gen_plugin.c
 *
 *  Created on: 26 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 *  Parse rules in .xml file, then generate .c file, then compile to a plugin .so file.
 */

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
	int ret;

	mmt_assert( argc == 3 || argc == 4, "Usage: %s lib_file.so property_file.xml include_dir", argv[0] );

	//read rule from .xml file
	rule_count = read_rules_from_file( argv[2], &rule_list );

	//generate rules to .c code
	generate_fsm( tmp_code_file, rule_list, rule_count );

	//compile code file
	if( argc == 3 )
		ret = compile_gen_code(argv[1], tmp_code_file, "./src/lib" );
	else
		ret = compile_gen_code(argv[1], tmp_code_file, argv[3] );

	//mmt_debug( "ret = %d", ret );
	if( ret == 0 )
		mmt_info( "Encoded %zu rules from \"%s\" to \"%s\"", rule_count, argv[2], argv[1] );
	else
		mmt_error( "Cannot encode rule \"%s\". Check options.", argv[1] );

	//free each rule
	for( i=0; i<rule_count; i++ )
		free_a_rule( rule_list[i], YES);

	mmt_mem_free( rule_list );
	return 0;
}
