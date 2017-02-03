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

  mmt_error("Execution trace:");

  for (i = 0; i < size; i++){
     fprintf(stderr, "\t %zu. %s\n", (i+1), strings[i]);

     //DEBUG_MODE given by Makefile
#ifdef DEBUG_MODE
     /* find first occurence of '(' or ' ' in message[i] and assume
      * everything before that is the file name. (Don't go beyond 0 though
      * (string terminator)*/
     size_t p = 0;
     while(strings[i][p] != '(' && strings[i][p] != ' '
   		  && strings[i][p] != 0)
   	  ++p;

     char syscom[256];


     sprintf(syscom,"addr2line %p -e %.*s", array[i] , (int)p, strings[i] );
     //last parameter is the filename of the symbol

     fprintf(stderr, "\t    ");
     if( system(syscom) ) {}
#endif

  }

  free (strings);
}


static const char *log_level_name[] ={ "INFO", "DEBUG", "WARN", "ERROR", "HALT" };

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
