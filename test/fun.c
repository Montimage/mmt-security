/*
 * fun.c
 *
 *  Created on: 22 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include <stdio.h>
void set( char buff[], char c, int index ){
	buff[ index ] = c;
}

void set_const( char *buff, const char c, int index ){
	*(buff + index)  = c;
}

struct string{
	char *data;
};

void set_string( struct string * buff, char c, int index ){
	buff->data[ index ] = c;
}

void set_string_const( const struct string *buff, char c, int index ){
	buff->data[ index ] = c;
}

void jump(char *buff, int index ){
	buff += index;
}

void jump_2(char **buff, int index ){
	*buff = *buff + index;
}

int main(){
	struct string str;
	char buff[10] = {'-','-','-','-','-','-','-','-','-','\0'};
	char *tmp;

	printf("buff=%s\n", buff);

	set( buff, 'N', 0 );
	printf("buff=%s\n", buff);

	set_const( buff, 'G', 0 );
	printf("buff=%s\n", buff);

	str.data = buff;
	set_string( &str, 'N', 0 );
	printf("buff=%s\n", buff);

	set_string_const( &str, 'G', 0 );
	printf("buff=%s\n", buff);

	jump( buff, 2 );
	printf("buff=%s\n", buff);

	tmp = buff;
	jump_2( &tmp, 2 );
	printf("buff=%s\n", tmp);
	return 0;
}
