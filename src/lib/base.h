/*
 * base.h
 *
 *  Created on: 21 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 *  Basic definitions/data struct
 */

#ifndef SRC_LIB_BASE_H_
#define SRC_LIB_BASE_H_

#include <stdlib.h>
#include <stdint.h>
//for uint64_t PRIu64
#include <inttypes.h>
#include <stdbool.h>

#define UNKNOWN -1
#define NO false
#define YES true

#define __check_null( x, y ) if( unlikely( x == NULL )) return y; else
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#endif /* SRC_LIB_BASE_H_ */
