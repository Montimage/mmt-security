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
#include <time.h>
#include "mmt_core.h"

void attributes_iterator(attribute_metadata_t * attribute, uint32_t proto_id,
		void * args) {
	int *attr_count = (int *) args;

	printf("%c\n\t { .id = %i, .data_type = %d, .name = \"%s\"}",
			(*attr_count == 0 ? ' ': ','),
			attribute->id, attribute->data_type, attribute->alias );
	(*attr_count) ++;
}

void protocols_iterator(uint32_t proto_id, void * args) {
	int *proto_count = (int *) args, attr_count = 0;

	printf("%c\n {.id = %i, .name = \"%s\", .attributes = (struct dpi_attribute[]){",
			 (*proto_count == 0? ' ': ','),
			proto_id, get_protocol_name_by_id(proto_id));

	iterate_through_protocol_attributes(proto_id, attributes_iterator, &attr_count );

	printf("},\n\t .attributes_count = %d\n }", attr_count );

	(*proto_count) ++;
}


int main(int argc, char** argv) {
	int proto_count = 0;
	char text[100];
	time_t now = time(NULL);
	struct tm *t = localtime(&now);
	strftime(text, sizeof(text)-1, "%Y-%m%d %H:%M:%S", t);

	printf("/**This code is generated automatically on %s.*/", text );
	printf("\n #ifndef MMT_DPI_H_\n #define MMT_DPI_H_");
	printf("\n #include <stdint.h>\n #include <stdlib.h>\n #include <string.h>");
	printf("\n struct dpi_attribute{\n\t uint16_t id;\n\t const char *name;\n\t long data_type;};");
	printf("\n struct dpi_proto{\n\t uint16_t id;\n\t const char *name;\n\t struct dpi_attribute *attributes;\n\t size_t attributes_count;};");

	printf("\n\n static const struct dpi_proto *DPI_PROTO = (struct dpi_proto[]){");
	init_extraction();

	iterate_through_protocols(protocols_iterator, &proto_count );

	close_extraction();

	printf( "};\n #define DPI_PROTO_SIZE %d\n ", proto_count );


	//avoid duplicate from data_types.h
	printf("\n #ifndef TYPES_DEFS_H" );
	printf("\n #define TYPES_DEFS_H" );
	printf("\nenum data_types { ");
	printf("\n    MMT_UNDEFINED_TYPE, /**< no type constant value */");
	printf("\n    MMT_U8_DATA, /**< unsigned 1-byte constant value */");
	printf("\n    MMT_U16_DATA, /**< unsigned 2-bytes constant value */");
	printf("\n    MMT_U32_DATA, /**< unsigned 4-bytes constant value */");
	printf("\n    MMT_U64_DATA, /**< unsigned 8-bytes constant value */");
	printf("\n    MMT_DATA_POINTER, /**< pointer constant value (size is void *) */");
	printf("\n    MMT_DATA_MAC_ADDR, /**< ethernet mac address constant value */");
	printf("\n    MMT_DATA_IP_NET, /**< ip network address constant value */");
	printf("\n    MMT_DATA_IP_ADDR, /**< ip address constant value */");
	printf("\n    MMT_DATA_IP6_ADDR, /**< ip6 address constant value */");
	printf("\n    MMT_DATA_PATH, /**< protocol path constant value */");
	printf("\n    MMT_DATA_TIMEVAL, /**< number of seconds and microseconds constant value */");
	printf("\n    MMT_DATA_BUFFER, /**< binary buffer content */");
	printf("\n    MMT_DATA_CHAR, /**< 1 character constant value */");
	printf("\n    MMT_DATA_PORT, /**< tcp/udp port constant value */");
	printf("\n    MMT_DATA_POINT, /**< point constant value */");
	printf("\n    MMT_DATA_PORT_RANGE, /**< tcp/udp port range constant value */");
	printf("\n    MMT_DATA_DATE, /**< date constant value */");
	printf("\n    MMT_DATA_TIMEARG, /**< time argument constant value */");
	printf("\n    MMT_DATA_STRING_INDEX, /**< string index constant value (an association between a string and an integer) */");
	printf("\n    MMT_DATA_FLOAT, /**< float constant value */");
	printf("\n    MMT_DATA_LAYERID, /**< Layer ID value */");
	printf("\n    MMT_DATA_FILTER_STATE, /**< (filter_id, filter_state) */");
	printf("\n    MMT_DATA_PARENT, /**< (filter_id, filter_state) */");
	printf("\n    MMT_STATS, /**< pointer to MMT Protocol statistics */");
	printf("\n    MMT_BINARY_DATA, /**< binary constant value */");
	printf("\n    MMT_BINARY_VAR_DATA, /**< binary constant value with variable size given by function getExtractionDataSizeByProtocolAndFieldIds */");
	printf("\n    MMT_STRING_DATA, /**< text string data constant value. Len plus data. Data is expected to be '\\0' terminated and maximum BINARY_64DATA_LEN long */");
	printf("\n    MMT_STRING_LONG_DATA, /**< text string data constant value. Len plus data. Data is expected to be '\\0' terminated and maximum STRING_DATA_LEN long */");
	printf("\n    MMT_HEADER_LINE, /**< string pointer value with a variable size. The string is not necessary null terminating */");
	printf("\n    MMT_GENERIC_HEADER_LINE, /**< structure representing an RFC2822 header line with null terminating field and value elements. */");
	printf("\n    MMT_STRING_DATA_POINTER, /**< pointer constant value (size is void *). The data pointed to is of type string with null terminating character included */");
	printf("\n};");
	printf("\n #endif" );

	//avoid duplicate from mmt_core.h
	printf("\n #ifndef MMT_CORE_H" );
	printf("\n #define MMT_CORE_H" );

	printf( "\n static inline uint32_t get_protocol_id_by_name( const char *name ){");
	printf( "\n	size_t i;");
	printf( "\n	for( i=0; i<DPI_PROTO_SIZE; i++ )");
	printf( "\n	if( strcmp( name, DPI_PROTO[i].name) == 0 )");
	printf( "\n	return DPI_PROTO[i].id;");
	printf( "\n	return -1;");
	printf( "\n}");

	printf( "\n static inline const char* get_protocol_name_by_id( uint32_t p_id ){");
	printf( "\n	size_t i;");
	printf( "\n	for( i=0; i<DPI_PROTO_SIZE; i++ )");
	printf( "\n	if( DPI_PROTO[i].id == p_id )" );
	printf( "\n	return DPI_PROTO[i].name;");
	printf( "\n	return NULL;");
	printf( "\n}");

	printf( "\n static inline uint32_t get_attribute_id_by_protocol_id_and_attribute_name( uint32_t p_id, const char*attr_name ){");
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

	printf( "\n static inline const char* get_attribute_name_by_protocol_id_and_attribute_id( uint32_t p_id, uint32_t attr_id ){");
	printf( "\n	size_t i; const struct dpi_proto *proto;");
	printf( "\n	for( i=0; i<DPI_PROTO_SIZE; i++ )");
	printf( "\n		if( DPI_PROTO[i].id == p_id ){");
	printf( "\n			proto = &( DPI_PROTO[i] );");
	printf( "\n			for( i=0; proto->attributes_count; i++ )");
	printf( "\n				if( proto->attributes[i].id == attr_id )");
	printf( "\n			return proto->attributes[i].name;");
	printf( "\n		}");
	printf( "\n	return NULL;");
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

	//end MMT_CORE_H
	printf("\n #endif" );

	printf( "\n#endif");
	return (EXIT_SUCCESS);
}

