/*
 * main_gen_dpi.c
 *
 *  Created on: 4 oct. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 *  Generate a list of available protocols and for each protocol, the list of its attributes
 *  The output is printed to the screen.
 *  By using this list, mmt-security can be independent from mmt-dpi, e.g., one does not need
 *  to install mmt-dpi to run mmt-security as all it needs is this list.
 *
 *  Note that mmt_sec_standalone.c still need mmt-dpi to extract packets' information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <mmt_core.h>

static uint32_t total_proto_att = 0;

static const char *data_type_name[] = {
		"MMT_UNDEFINED_TYPE",  " /**< no type constant value */",
		"MMT_U8_DATA",  " /**< unsigned 1-byte constant value */",
		"MMT_U16_DATA",  " /**< unsigned 2-bytes constant value */",
		"MMT_U32_DATA",  " /**< unsigned 4-bytes constant value */",
		"MMT_U64_DATA",  " /**< unsigned 8-bytes constant value */",
		"MMT_DATA_POINTER",  " /**< pointer constant value (size is void *) */",
		"MMT_DATA_MAC_ADDR",  " /**< ethernet mac address constant value */",
		"MMT_DATA_IP_NET",  " /**< ip network address constant value */",
		"MMT_DATA_IP_ADDR",  " /**< ip address constant value */",
		"MMT_DATA_IP6_ADDR",  " /**< ip6 address constant value */",
		"MMT_DATA_PATH",  " /**< protocol path constant value */",
		"MMT_DATA_TIMEVAL",  " /**< number of seconds and microseconds constant value */",
		"MMT_DATA_BUFFER",  " /**< binary buffer content */",
		"MMT_DATA_CHAR",  " /**< 1 character constant value */",
		"MMT_DATA_PORT",  " /**< tcp/udp port constant value */",
		"MMT_DATA_POINT",  " /**< point constant value */",
		"MMT_DATA_PORT_RANGE",  " /**< tcp/udp port range constant value */",
		"MMT_DATA_DATE",  " /**< date constant value */",
		"MMT_DATA_TIMEARG",  " /**< time argument constant value */",
		"MMT_DATA_STRING_INDEX",  " /**< string index constant value (an association between a string and an integer) */",
		"MMT_DATA_FLOAT",  " /**< float constant value */",
		"MMT_DATA_LAYERID",  " /**< Layer ID value */",
		"MMT_DATA_FILTER_STATE",  " /**< (filter_id, filter_state) */",
		"MMT_DATA_PARENT",  " /**< (filter_id, filter_state) */",
		"MMT_STATS",  " /**< pointer to MMT Protocol statistics */",
		"MMT_BINARY_DATA",  " /**< binary constant value */",
		"MMT_BINARY_VAR_DATA",  " /**< binary constant value with variable size given by function getExtractionDataSizeByProtocolAndFieldIds */",
		"MMT_STRING_DATA",  " /**< text string data constant value. Len plus data. Data is expected to be '\\0' terminated and maximum BINARY_64DATA_LEN long */",
		"MMT_STRING_LONG_DATA",  " /**< text string data constant value. Len plus data. Data is expected to be '\\0' terminated and maximum STRING_DATA_LEN long */",
		"MMT_HEADER_LINE",  " /**< string pointer value with a variable size. The string is not necessary null terminating */",
		"MMT_GENERIC_HEADER_LINE",  " /**< structure representing an RFC2822 header line with null terminating field and value elements. */",
		"MMT_STRING_DATA_POINTER",  " /**< pointer constant value (size is void *). The data pointed to is of type string with null terminating character included */",
};
const uint16_t data_type_count = 32;


void attributes_iterator(attribute_metadata_t * attribute, uint32_t proto_id,
		void * args) {
	int *attr_count = (int *) args;

	printf("%c\n\t { .gid = %5d, .id = %4i, .data_type = %-23s, .name = \"%s\"}",
			(*attr_count == 0 ? ' ': ','),
			++total_proto_att,
			attribute->id,
			data_type_name[ attribute->data_type * 2 ],
			attribute->alias);
	(*attr_count) ++;
}

void protocols_iterator(uint32_t proto_id, void * args) {
	int *proto_count = (int *) args, attr_count = 0;

	if( *proto_count > proto_id ){
		fprintf( stderr, "ERROR: duplicated protocol id %d\n", proto_id );
		return;
	}

	//dummy protocol
	while( *proto_count < proto_id ){
		printf("//dummy");
		printf("%c\n{.id = %i, .name = NULL, .attributes = NULL, .attributes_count = 0}",
				(*proto_count == 0? ' ': ','), *proto_count );
		(*proto_count) ++;
	}

	printf("%c\n {.id = %i, .name = \"%s\", .attributes = (struct dpi_attribute[]){",
			 (*proto_count == 0? ' ': ','),
			proto_id, ( get_protocol_name_by_id(proto_id) ));

	iterate_through_protocol_attributes(proto_id, attributes_iterator, &attr_count );

	printf("},\n\t .attributes_count = %d\n }", attr_count );

	(*proto_count) ++;
}


int main(int argc, char** argv) {
	int proto_count = 0;
	char text[100];
	time_t now = time(NULL);
	struct tm *t = localtime(&now);
	int i;

	strftime(text, sizeof(text)-1, "%Y-%m%d %H:%M:%S", t);

	printf("/**This code is generated automatically on %s.*/", text );

	printf("\n #ifndef __MMT_SEC_DPI_H_\n #define __MMT_SEC_DPI_H_");
	printf("\n #include <stdint.h>\n #include <stdlib.h>\n #include <string.h>");

	//avoid duplicate from data_types.h
	printf("\n\n #ifndef TYPES_DEFS_H" );
	printf("\n #define TYPES_DEFS_H" );
	printf("\nenum data_types { ");
	for( i=0; i<data_type_count; i++ )
		printf("\n\t %s, %s", data_type_name[i*2], data_type_name[i*2+1] );
	printf("\n};");
	printf("\n #endif //end TYPES_DEFS_H\n" );

	printf("\n\n static const char *dpi_data_types_name[] = {" );
	for( i=0; i<data_type_count; i++ )
		printf("\n\t \"%s\", %s", data_type_name[i*2], data_type_name[i*2+1] );
	printf("\n };\n");

	printf("\n struct dpi_attribute{\n\t uint32_t gid; \n\t uint16_t id;\n\t const char *name;\n\t long data_type;};");
	printf("\n struct dpi_proto{\n\t uint16_t id;\n\t const char *name;\n\t struct dpi_attribute *attributes;\n\t size_t attributes_count;};");


	printf("\n\n static const struct dpi_proto *DPI_PROTO = (struct dpi_proto[]){");

	init_extraction();
	iterate_through_protocols( protocols_iterator, &proto_count );
	close_extraction();

	printf("}; //TYPES_DEFS_H\n"); //end of struct


	printf( "\n #define DPI_PROTO_SIZE %d", proto_count );
	printf( "\n #define DPI_PROTO_ATT_SIZE %d\n", total_proto_att );

	printf("\n #ifndef MMT_CORE_H\n #define MMT_CORE_H");

	printf( "\n static inline uint32_t get_protocol_id_by_name( const char *name ){");
	printf( "\n	size_t i;");
	printf( "\n	for( i=0; i<DPI_PROTO_SIZE; i++ )");
	printf( "\n	if( strcmp( name, DPI_PROTO[i].name) == 0 )");
	printf( "\n	return DPI_PROTO[i].id;");
	printf( "\n	return -1;");
	printf( "\n}");

	printf( "\n static inline const char* get_protocol_name_by_id( uint32_t p_id ){");
	printf( "\n	size_t i;");
	printf( "\n	if( p_id >= DPI_PROTO_SIZE ) return NULL; ");
	printf( "\n	return DPI_PROTO[ p_id ].name;");
	printf( "\n}");

	printf( "\n static inline uint32_t get_attribute_id_by_protocol_id_and_attribute_name( uint32_t p_id, const char*attr_name ){");
	printf( "\n	size_t i; const struct dpi_proto *proto;");
	printf( "\n	if( p_id >= DPI_PROTO_SIZE ) return -1; ");
	printf( "\n	proto = &( DPI_PROTO[ p_id ] );");
	printf( "\n	for( i=0; i<proto->attributes_count; i++ )");
	printf( "\n		if( strcmp(attr_name, proto->attributes[i].name) == 0 )");
	printf( "\n			return proto->attributes[i].id;");
	printf( "\n	return -1;");
	printf( "\n}");

	printf( "\n static inline const char* get_attribute_id_by_protocol_id_and_attribute_id( uint32_t p_id, uint32_t attr_id ){");
	printf( "\n	size_t i; const struct dpi_proto *proto;");
	printf( "\n	if( p_id >= DPI_PROTO_SIZE ) return NULL; ");
	printf( "\n	proto = &( DPI_PROTO[ p_id ] );");
	printf( "\n	for( i=0; i<proto->attributes_count; i++ )");
	printf( "\n		if( proto->attributes[i].id == attr_id )");
	printf( "\n			return proto->attributes[i].name;");
	printf( "\n	return NULL;");
	printf( "\n}");

	printf( "\nstatic inline long get_attribute_data_type( uint32_t p_id, uint32_t a_id ){");
	printf( "\n	size_t i; const struct dpi_proto *proto;");
	printf( "\n	if( p_id >= DPI_PROTO_SIZE ) return -1; ");
	printf( "\n	proto = &( DPI_PROTO[ p_id ] );");
	printf( "\n	for( i=0; i<proto->attributes_count; i++ )");
	printf( "\n		if( a_id == proto->attributes[i].id )");
	printf( "\n			return proto->attributes[i].data_type;");
	printf( "\n	return -1;");
	printf( "\n}");

	printf( "\n#endif //MMT_CORE_H");

	printf( "\nstatic inline long get_attribute_index( uint32_t p_id, uint32_t a_id ){");
	printf( "\n	size_t i; const struct dpi_proto *proto;");
	printf( "\n	if( p_id >= DPI_PROTO_SIZE ) return -1; ");
	printf( "\n	proto = &( DPI_PROTO[ p_id ] );");
	printf( "\n	for( i=0; i<proto->attributes_count; i++ )");
	printf( "\n		if( a_id == proto->attributes[i].id )");
	printf( "\n			return proto->attributes[i].gid;");
	printf( "\n	return -1;");
	printf( "\n}");

	printf( "\n#endif //__MMT_SEC_DPI_H_");

	return (EXIT_SUCCESS);
}

