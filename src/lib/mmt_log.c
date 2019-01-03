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


#ifdef DEBUG_MODE
	#warning "This compile option is reserved only for debugging"
#endif

/* Obtain a backtrace and print it to stdou. */
void mmt_print_execution_trace (void) {
  void *array[10];
  size_t size;
  char **strings;
  size_t i;
  size    = backtrace (array, 10);
  strings = backtrace_symbols (array, size);

  mmt_error("Execution trace:");

  //i=2: ignore 2 first elements in trace as they are: this fun, then mmt_log
  for (i = 2; i < size; i++){
     fprintf(stderr, "\t %zu. %s\n", (i-1), strings[i]);

     //DEBUG_MODE given by Makefile
#ifdef DEBUG_MODE
     /* find first occurence of '(' or ' ' in message[i] and assume
      * everything before that is the file name. (Don't go beyond 0 though
      * (string terminator)*/
     size_t p = 0, size;
     while(strings[i][p] != '(' && strings[i][p] != ' '
   		  && strings[i][p] != 0)
   	  ++p;

     char syscom[256];


     size = snprintf(syscom, sizeof( syscom ), "addr2line %p -e %.*s", array[i] , (int)p, strings[i] );
     syscom[size] = '\0';
     //last parameter is the filename of the symbol

     fprintf(stderr, "\t    ");
     if( system(syscom) ) {}
#endif

  }

  free (strings);
}


static const char *log_level_name[] ={ "INFO", "DEBUG", "WARN", "ERROR", "HALT" };

void mmt_sec_log( log_level_t level, const char *format, ... ){
	va_list arg;
	//TODO limit mmt_log on 100K characters
	char buffer[100000];
	/* Write the error message */
	va_start(arg, format);
	vsnprintf(buffer, 100000, format, arg);
	if( level == HALT || level == ERROR || level == WARN )
		fprintf(stderr, "%s_SEC: %s\n", log_level_name[level], buffer);
	else
		fprintf(stdout, "%s_SEC: %s\n", log_level_name[level], buffer);

	va_end(arg);

	if( unlikely( level == HALT )){

		mmt_print_execution_trace();

		exit( EXIT_FAILURE );
	}
}
