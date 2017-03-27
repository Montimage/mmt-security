/*
 * log.c
 *
 *  Created on: 19 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "../src/lib/mmt_log.h"
#include "minunit.h"

int tests_run = 0;

 int foo = 7;
 int bar = 4;


static char * test_foo() {
	mu_assert("error, foo != 7", foo == 7);
	return 0;
}

static char * test_bar() {
	mu_assert("error, bar != 5", bar == 5);
	return 0;
}

static char * all_tests() {
	mu_run_test(test_foo);
	mu_run_test(test_bar);
	return 0;
}

int main() {
	char *result = all_tests();
	if (result != 0) {
		mmt_sec_log( HALT,"Tests fail: %s", result );
	}
	else {
		printf("ALL TESTS PASSED\n");
	}
	mmt_sec_log( INFO,"Tests run: %d\n", tests_run );

	return result != 0;
}
