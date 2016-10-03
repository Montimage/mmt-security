/*
 * bool_expression.h
 *
 *  Created on: 21 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 *  Boolean expression of an event
 */

#ifndef SRC_LIB_EXPRESSION_H_
#define SRC_LIB_EXPRESSION_H_

#include <stdlib.h>
#include <stdint.h>

#include "data_struct.h"

enum data_type{
	NUMERIC, STRING
};
/**
 * Constant
 */
typedef struct{
	enum data_type type;
	/**
	 * size of the pointer *data
	 */
	size_t data_size;
	void *data;
} constant_t;

/**
 * Variable
 */
typedef struct{
	enum data_type type;
	//a variable: TCP.SRC or TCP.SRC.1
	char *proto, *att;
	uint8_t ref_index;
} variable_t;


enum operator{
	//boolean operator: or, and
  OR, AND,
  NOT,
  //comparison operators: not equal, equal, ...
  NEQ, EQ, GT, GTE, LT, LTE,
  //numeric operators: + - * /
  ADD, SUB, MUL, DIV,
  //a embedded function
  FUNCTION
};


/**
 * Expression that is x-ary expression:
 * that can be a function: name( param_1, param_2, ...)
 * or a boolean expression: or( param_1, param_2, ...)
 * or a calculation expression: *( param_1, param_2, ... )
 */
typedef struct operation_struct{
	//type id of return data
	uint8_t data_type_id;
	enum operator operator;

	/**
	 * Representation of operator in plain text
	 * that is either a function name or an operator
	 */
	char *name;
	/**
	 * Number of parameters
	 */
	size_t params_size;
	/**
	 * List of parameters, it data has type expression_t
	 */
	link_node_t *params_list;
}operation_t;

/**
 * An expression is either a variable, or a constant, or an operation
 */
typedef struct expression_struct{
	enum expression { VARIABLE, CONSTANT, OPERATION} type;

	union{
		constant_t *constant;
		variable_t *variable;
		operation_t *operation;
	};
	struct expression_struct *father;
}expression_t;



/**
 * Get a set of variables (distinguished by "proto" and "att") of an expression.
 * - Input:
 * 	+ expr
 * - Output:
 * 	+ create and assign a map containing unique variables
 * - Return:
 * 	+ number of unique variables
 */
size_t get_unique_variables_of_expression( const expression_t *expr, mmt_map_t **variables_map );

/**
 * Parse a string to get expression
 * - Input
 * 	+ string:
 * 	+ size  : size of the string
 * - Output
 * 	+ expr  : that is a pointer points to the result
 * - Return
 * 	+ O if success
 * 	+ error code if fail
 * - Note:
 * 	use mmt_free to free the expr when one does not need it anymore
 */
int parse_expression( expression_t **expr, const char *string, size_t size );

/**
 * Convert an expression to a string
 * - Input
 *    + expr: the expression to be stringified
 * - Output
 *    + string that is a pointer points to the result.
 * - Return
 * 	+ the size of the result string
 * - Note:
 * 	use mmt_free to free the string when one does not need it anymore
 */
size_t expr_stringify_constant( char **string, const constant_t *expr);
size_t expr_stringify_variable( char **string, const variable_t *expr);
size_t expr_stringify_expression( char **string, const expression_t *expr);


constant_t *expr_create_a_constant( enum data_type type, size_t data_size, void *data );
variable_t *expr_create_a_variable( char *proto, char *attr, uint8_t ref_index );
operation_t *expr_create_an_operation( char *name, enum operator operator );
expression_t *expr_create_an_expression( enum expression type, void *data );

/**
 * Free a constant
 */
void expr_free_a_constant( constant_t *, enum bool free_data);
void expr_free_a_variable( variable_t *, enum bool free_data);
void expr_free_an_operation( operation_t *, enum bool free_data);
void expr_free_an_expression( expression_t *, enum bool free_data);

constant_t *evaluate_expression( const expression_t *expr, const constant_t **constants, size_t const_size );
#endif /* SRC_LIB_EXPRESSION_H_ */
