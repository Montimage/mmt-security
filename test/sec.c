/*
 * sec.c
 *
 *  Created on: Oct 11, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */
#include "../src/lib/mmt_alloc.h"
#include "../src/lib/mmt_log.h"
#include "../src/lib/mmt_security.h"

double double_2 = 2;
double double_22 = 22;
double double_18 = 18;
message_element_t *elements[2] = {
	(message_element_t[]){
		{.proto_id = 354, .att_id = 6, .data = &double_2}, //tcp - flags
		{.proto_id = 354, .att_id = 2, .data = &double_22},//tcp - dest_port
		{.proto_id = 178, .att_id = 12, .data = "1.1.1.1"},
		{.proto_id = 178, .att_id = 13, .data = "0.0.0.0"}
	},
	(message_element_t[]){
		{.proto_id = 354, .att_id = 6, .data = &double_18},
		{.proto_id = 354, .att_id = 1, .data = &double_22},
		{.proto_id = 178, .att_id = 12, .data = "0.0.0.0"},
		{.proto_id = 178, .att_id = 13, .data = "1.1.1.1"}
	}
};

static message_t messages[] = ( message_t[]){
	{.counter = 1, .timestamp = 0, .elements_count = 0, .elements = NULL },
	{.counter = 3, .timestamp = 0, .elements_count = 0, .elements = NULL }
};

void callback( uint32_t rule_id,		//id of rule
		uint64_t timestamp,  //moment the rule is validated
		uint32_t counter,
		const mmt_map_t *trace,
		void *user_data ){
}

int main( int argc, char **argv ){
	const rule_info_t **rules_array;
	size_t size, i,j;
	mmt_sec_handler_t *handler;
	size = mmt_sec_get_rules_info( &rules_array );
	handler = mmt_sec_register( rules_array, size, callback, NULL );


	size = sizeof( messages ) / sizeof( message_t );
	mmt_debug( "Testing %zu messages ... ", size );

	//for each message
	for( i=0; i<size; i++ ){
		messages[i].elements_count = 4; //sizeof( elements[i] ) / sizeof( message_element_t* );
		messages[i].elements = mmt_malloc( sizeof( void *) * messages[i].elements_count );
		//for each message
		for( j=0; j<messages[i].elements_count; j++ )
			messages[i].elements[j] = &elements[i][j];

		mmt_sec_process( handler, &messages[i] );
	}

	for( i=0; i<size; i++ ){
		mmt_free( messages[i].elements );
	}
	mmt_sec_unregister( handler );
	mmt_free( rules_array );
	return 0;
}
