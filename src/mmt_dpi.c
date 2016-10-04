/*
 * dpi_proto_attribute.c
 *
 *  Created on: 4 oct. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

/**
 * This example is intened to provide the list of available protocols and for each protocol, the list of its attributes
 *
 * Compile this example with:
 *
 * gcc -I/opt/mmt/dpi/include -L/opt/mmt/dpi/lib -lmmt_core -o proto dpi_proto_attribute.c -lmmt_core -ldl
 *
 * Then execute the program:
 *
 * ./proto > proto_attr_output.h
 *
 * The output in the file proto_attr_output.h
 *
 * 	That is it!
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include "mmt_core.h"

void attributes_iterator(attribute_metadata_t * attribute, uint32_t proto_id,
		void * args) {
	int *attr_count = (int *) args;

	printf("%c\n\t{ .id = %i, .data_type = %d, .name = \"%s\"}",
			(*attr_count == 0 ? ' ': ','),
			attribute->id, attribute->data_type, attribute->alias );
	(*attr_count) ++;
}

void protocols_iterator(uint32_t proto_id, void * args) {
	int *proto_count = (int *) args, attr_count = 0;

	printf("%c\n{.id = %i, .name = \"%s\", .attributes = (struct dpi_attribute[]){",
			 (*proto_count == 0? ' ': ','),
			proto_id, get_protocol_name_by_id(proto_id));

	iterate_through_protocol_attributes(proto_id, attributes_iterator, &attr_count );

	printf("},\n\t.attributes_count = %d\n}", attr_count );

	(*proto_count) ++;
}

int main(int argc, char** argv) {
	int proto_count = 0;
	printf("/**This code is generated automatically. Do not modify it manually.*/");
	printf("\n#ifndef MMT_DPI_H_\n#define MMT_DPI_H_");
	printf("\n#include <stdint.h>\n#include <stdlib.h>\n#include <string.h>");
	printf("\nstruct dpi_attribute{\n\tuint16_t id;\n\tconst char *name;\n\tlong data_type;};");
	printf("\nstruct dpi_proto{\n\tuint16_t id;\n\tconst char *name;\n\tstruct dpi_attribute *attributes;\n\tsize_t attributes_count;};");

	printf("\n\nconst struct dpi_proto *DPI_PROTO = (struct dpi_proto[]){");
	init_extraction();

	iterate_through_protocols(protocols_iterator, &proto_count );

	close_extraction();

	printf( "};\n#define DPI_PROTO_SIZE %d\n", proto_count );
	printf( "\nstatic inline uint32_t get_protocol_id_by_name( const char *name ){");
	printf( "\n	size_t i;");
	printf( "\n	for( i=0; i<DPI_PROTO_SIZE; i++ )");
	printf( "\n	if( strcmp( name, DPI_PROTO[i].name) == 0 )");
	printf( "\n	return DPI_PROTO[i].id;");
	printf( "\n	return -1;");
	printf( "\n}");

	printf( "\nstatic inline uint32_t get_attribute_id_by_protocol_id_and_attribute_name( uint32_t p_id, const char*attr_name ){");
	printf( "\n	size_t i; const struct dpi_proto *proto;");
	printf( "\n	for( i=0; i<DPI_PROTO_SIZE; i++ )");
	printf( "\n		if( DPI_PROTO[i].id == p_id ){");
	printf( "\n			proto = &( DPI_PROTO[i] );");
	printf( "\n			for( i=0; proto->attributes_count; i++ )");
	printf( "\n				if( strcmp(attr_name, proto->attributes[i].name) == 0 )");
	printf( "\n			return proto->attributes[i].id;");
	printf( "\n		}");
	printf( "\n	return -1;");
	printf( "\n}");

	printf( "\nstatic inline long get_attribute_data_type( uint32_t p_id, uint32_t a_id ){");
	printf( "\n	size_t i; const struct dpi_proto *proto;");
	printf( "\n	for( i=0; i<DPI_PROTO_SIZE; i++ )");
	printf( "\n		if( DPI_PROTO[i].id == p_id ){");
	printf( "\n			proto = &( DPI_PROTO[i] );");
	printf( "\n			for( i=0; proto->attributes_count; i++ )");
	printf( "\n				if( a_id == proto->attributes[i].id )");
	printf( "\n			return proto->attributes[i].data_type;");
	printf( "\n		}");
	printf( "\n	return -1;");
	printf( "\n}");

	printf( "\n#endif");
	return (EXIT_SUCCESS);
}

