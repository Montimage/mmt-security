/*
 * mmt_log.c
 *
 *  Created on: 19 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include <stdlib.h>
#include "mmt_log.h"
#include "mmt_alloc.h"

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
		exit( 1 );
	}
}
