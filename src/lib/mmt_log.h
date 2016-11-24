/*
 * mmt_log.h
 *
 *  Created on: 19 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_LOG_H_
#define SRC_LOG_H_

#include <stdio.h>
#include <stdarg.h>
#include "base.h"

typedef enum {
	INFO, DEBUG, WARN, ERROR, HALT
} log_level_t;

/*
 * logging information
 * - Input:
 * 	+ level: log level
 * 		use HALT to exit the system after logging the message
 * 	+ format: same as #printf function
 */
void mmt_log( log_level_t level, const char *format, ... )
	__attribute__((format (printf, 2, 3)));

#define mmt_warn( ... )  mmt_log( WARN, __VA_ARGS__ )
#define mmt_info( ... )  mmt_log( INFO, __VA_ARGS__ )
#define mmt_error( ... ) mmt_log( ERROR, __VA_ARGS__ )



#ifdef DEBUG_MODE
	#define mmt_debug(...)   do{ printf("%s:%d ", __FILE__, __LINE__); mmt_log( DEBUG, __VA_ARGS__ ); fflush( stdout ); } while(0)
	#define mmt_halt( ... )  do{ printf("%s:%d ", __FILE__, __LINE__); mmt_log( HALT, __VA_ARGS__ ); }while( 0 )
	#define mmt_assert( expr, ... ) while( unlikely( !(expr) ) ){ printf("%s:%d ", __FILE__, __LINE__); mmt_log( HALT, __VA_ARGS__ ); break; }
#else
	#define mmt_debug(...)
	#define mmt_halt( ... ) mmt_log( HALT, __VA_ARGS__ )
	#define mmt_assert( expr, ... ) while( unlikely( !(expr) ) ){ mmt_log( HALT, __VA_ARGS__ ); break; }
#endif

void mmt_print_execution_trace();

#endif /* SRC_LOG_H_ */
