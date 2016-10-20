/*
 * main_rule_info.c
 *
 *  Created on: Oct 10, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 *  Get information of rules encoded in a binary file (.so)
 */
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include "lib/base.h"
#include "lib/mmt_log.h"
#include "lib/mmt_alloc.h"
#include "lib/plugins_engine.h"

int main( int argc, char** argv ){
	const rule_info_t **rules_arr;
	size_t i, j, n;

	mmt_assert( argc <= 2, "Usage: %s [lib_file.so]", argv[0] );
	//load plugins from default folder:
	// - /opt/mmt/security/plugins
	// - ./plugins
	if( argc == 1)
		n = load_mmt_sec_rules( &rules_arr );
	else
		n = load_mmt_sec_rule( &rules_arr, argv[1] );

	printf("Found %zu rule%s", n, n<=1? ".": "s." );

	for( i=0; i<n; i++ ){
		printf("\n%zu - Rule id: %d", (i+1), rules_arr[i]->id );
		printf("\n\t- type            : %s",  rules_arr[i]->type_string );
		printf("\n\t- events_count    : %d",  rules_arr[i]->events_count );
		printf("\n\t- variables_count : %zu",  rules_arr[i]->proto_atts_count );
		printf("\n\t- variables       : " );
		for( j=0; j<rules_arr[i]->proto_atts_count; j++ )
			printf( "%s%s.%s",
					j==0? "":", ",
					rules_arr[i]->proto_atts[j].proto, rules_arr[i]->proto_atts[j].att);

		printf("\n\t- description     : %s",  rules_arr[i]->description );
		printf("\n\t- if_satisfied    : %s",  rules_arr[i]->if_satisfied );
		printf("\n\t- if_not_satisfied: %s",  rules_arr[i]->if_not_satisfied );
		printf("\n\t- create_instance : %p",  rules_arr[i]->create_instance );
		printf("\n\t- convert_message : %p",  rules_arr[i]->convert_message );
		printf("\n\t- hash_message    : %p",  rules_arr[i]->hash_message );
	}
	printf("\n");
	mmt_mem_free( rules_arr );
	return 0;
}
