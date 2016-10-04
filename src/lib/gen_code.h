/*
 * gen_code.h
 *
 *  Created on: 4 oct. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_LIB_GEN_CODE_H_
#define SRC_LIB_GEN_CODE_H_

#include "base.h"
#include "rule.h"

enum bool generate_fsm( const char* file_name, rule_t *const*rules, size_t count );

enum bool compile_gen_code( const char *file_name );

#endif /* SRC_LIB_GEN_CODE_H_ */
