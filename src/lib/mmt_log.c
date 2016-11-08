/*
 * mmt_log.c
 *
 *  Created on: 19 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include "mmt_log.h"

/* Obtain a backtrace and print it to stdou. */
void mmt_print_execution_trace (void) {
  void *array[10];
  size_t size;
  char **strings;
  size_t i;

  size    = backtrace (array, 10);
  strings = backtrace_symbols (array, size);

  mmt_error("Obtained %zd stack frames:", size);

  for (i = 0; i < size; i++)
     mmt_error("%zu. %s", i, strings[i]);

  free (strings);
}


static char *log_level_name[] ={ "INFO", "DEBUG", "WARN", "ERROR", "HALT" };

void mmt_log( log_level_t level, const char *format, ... ){
	va_list arg;
	char buffer[1024];
	/* Write the error message */
	va_start(arg, format);
	vsprintf(buffer, format, arg);
	if( level == HALT || level == ERROR || level == WARN )
		fprintf(stderr, "%s - %s\n", log_level_name[level], buffer);
	else
		fprintf(stdout, "%s - %s\n", log_level_name[level], buffer);
	va_end(arg);
	if( level == HALT ){
		mmt_print_execution_trace();
		exit( 1 );
	}
}
