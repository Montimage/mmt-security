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
	const rule_info_t *rules_arr;
	size_t i, n;

	mmt_assert( argc == 2, "Usage: %s lib_file.so", argv[0] );

	n = load_plugin( &rules_arr, argv[1] );
	printf("There are %zu rules in file %s", n, argv[1] );
	for( i=0; i<n; i++ ){
		printf("\n%zu - Rule id: %zu", (i+1), rules_arr[i].id );
		printf("\n\t- description     : %s",  rules_arr[i].description );
		printf("\n\t- if_satisfied    : %s",  rules_arr[i].if_satisfied );
		printf("\n\t- if_not_satisfied: %s",  rules_arr[i].if_not_satisfied );
	}
	printf("\n");
	return 0;
}
