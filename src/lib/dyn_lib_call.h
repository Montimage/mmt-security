/*
 * dyn_lib_call.h
 *
 *  Created on: 19 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_DYN_LIB_CALL_H_
#define SRC_DYN_LIB_CALL_H_

int funct_get_return_type_and_size(int *size, char *lib_name, char *funct_name);

/**
 * Execute a function in lib_name
 */
void *funct_execute( const char *lib_name, const char *fn_name, size_t param_size, const void **param_ptr,  size_t data_size);
#endif /* SRC_DYN_LIB_CALL_H_ */
