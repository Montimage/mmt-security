/*
 * expression.c
 *
 *  Created on: 21 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "../src/lib/base.h"
#include "../src/lib/expression.h"
#include "../src/lib/mmt_log.h"
#include "../src/lib/mmt_alloc.h"

size_t _parse_constant( constant_t **expr, const char *string, size_t string_size );
size_t _parse_variable( variable_t **expr, const char *string, size_t string_size );
size_t _parse_a_name( char **name,  const char *string, size_t string_size );
size_t _parse_a_string( char **str, const char *string, size_t string_size );
size_t _parse_a_number( double*, const char *string, size_t string_size );
int main(){
	expression_t *expr;
	constant_t *cont = NULL;
	char *s = NULL, *s1, *temp = NULL;
	char *name = NULL;
	bool ret = NO;
	size_t str_size = 10, index=0;
	variable_t *var = NULL;

	mmt_assert( (_parse_constant(&cont, s, 0) == NO), "Not good for NULL" );

	s1 = s = mmt_mem_alloc( 10 );
	bzero( s, 10 );


	s[0] = ' ';s[1] = 'y';s[2] = '0';s[3] = ' ';
	index = _parse_a_name(&name, s1, str_size);
	mmt_debug( "name = %s", name );
	mmt_assert( (name[0] == 'y' && index == 3) , "Not good for a name: %zu - %s", index, name );

	mmt_mem_free( name );
	name = NULL;
	s[0] = '"';s[1] = 'x';s[2] = 'x';s[3] = '"';
	index = _parse_a_string( &name, s1, str_size);
	mmt_debug( "string = %s", name );
	mmt_assert( ( index == 4 ), "Not good for string" );

	mmt_mem_free( name );
	s[0] = 'x';s[1] = '.';s[2] = 'y';s[3] = ' ';
	index = _parse_variable(&var, s1, str_size);
	mmt_assert(  var != NULL && index == 3, "Not good for variable" );
	mmt_debug( "variable = %s#%s", var->proto, var->att );

	mmt_mem_free( var->proto );
	mmt_mem_free( var->att );
	mmt_mem_free( var );
	s[0] = 'x';s[1] = '.';s[2] = 'y';s[3] = '.',s[4] = '1',s[5] = '8';
	index = _parse_variable(&var, s1, str_size);
	mmt_assert(  var != NULL && index == 6, "Not good for variable with ref_index" );
	mmt_debug( "variable = %s#%s%d", var->proto, var->att, var->ref_index );

	mmt_assert( expr_stringify_variable( &temp, var ) > 0, "Stringify is incorrect");
	mmt_debug("variable: %s", temp );

	s[3] = 'z'; s[4] = '.'; s[5] = '5'; s[6] = '8';
	mmt_assert( (_parse_variable(&var, s1, str_size) == YES ), "Not good for variable" );

	mmt_assert( expr_stringify_variable( &temp, var ) > 0, "Stringify is incorrect");
	mmt_debug("variable: %s", temp );

	s[3] = 'x';
	mmt_assert( (_parse_constant(&cont, s1, str_size) == NO ), "Not good for open string" );

	printf("OK\n");
	return 0;
}
