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

typedef enum {
	INFO, DEBUG, WARN, ERROR, HALT
} log_level_t;

/*
 * logging information
 * - Input:
 * 	+ level: log level
 * 		use level.HALT to exit the system after logging the message
 * 	+ format: same as pr
 */
void mmt_log( log_level_t level, const char *format, ... )
	__attribute__((format (printf, 2, 3)));

#define mmt_halt( ... ) mmt_log( HALT, __VA_ARGS__ )
#define mmt_assert( expr, ... ) if( !(expr) ) mmt_log( HALT, __VA_ARGS__ )

#define mmt_debug(...) printf("%s:%d ", __FILE__, __LINE__); mmt_log( DEBUG, __VA_ARGS__ )



#endif /* SRC_LOG_H_ */
