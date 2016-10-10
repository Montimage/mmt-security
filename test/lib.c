/*
 * lib.c
 *
 *  Created on: 7 oct. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */


#include <stdio.h>
#include <stdint.h>

#include "../src/lib/plugin_header.h"

int main(void){
	const rule_info_t *rules_arr;
	size_t i, n;
	puts("This is a shared library test...");
	n = get_rules_information( &rules_arr );
	for( i=0; i<n; i++ ){
		printf("\n%zu - Rule %zu: %s", i, rules_arr[i].id, rules_arr[i].description );
		//rules_arr[i].description = "abc";
	}
	return 0;
}
