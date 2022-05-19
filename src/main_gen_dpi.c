/*
 * main_gen_dpi.c
 *
 *  Created on: 4 oct. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 *  Generate a list of available protocols and for each protocol, the list of its attributes
 *  The output is printed to the screen or to file (if having one running parameter that represent a file path).
 *  By using this list, mmt-security can be independent from mmt-dpi, e.g., one does not need
 *  to install mmt-dpi to run mmt-security as all it needs is this list.
 *
 *  Note that mmt_sec_standalone.c still need mmt-dpi to extract packets' information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <mmt_core.h>


static uint32_t total_proto_att = 0;
static FILE *output = NULL;

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
		"MMT_U16_ARRAY", "/**< array of uint16_t */",
		"MMT_U32_ARRAY", "/**< array of uint32_t */",
		"MMT_U64_ARRAY", "/**< array of uint64_t */",
};
const uint16_t data_type_count = sizeof( data_type_name ) / sizeof(data_type_name[0]) / 2;


void attributes_iterator(attribute_metadata_t * attribute, uint32_t proto_id,
		void * args) {
	int *attr_count = (int *) args;

	fprintf( output,"%c\n\t { .gid = %5"PRIu32", .id = %4"PRIu32", .data_type = %-23s, .name = \"%s\"}",
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
		fprintf( output,"%c\n{.id = %i, .name = NULL, .attributes = NULL, .attributes_count = 0}/*dummy*/",
				(*proto_count == 0? ' ': ','), *proto_count );
		(*proto_count) ++;
	}

	fprintf( output,"%c\n {.id = %"PRIu32", .name = \"%s\", .attributes = (struct dpi_attribute[]){",
			 (*proto_count == 0? ' ': ','),
			proto_id, ( get_protocol_name_by_id(proto_id) ));

	iterate_through_protocol_attributes(proto_id, attributes_iterator, &attr_count );

	fprintf( output,"},\n\t .attributes_count = %d\n }", attr_count );

	(*proto_count) ++;
}


int main(int argc, char** argv) {
	int proto_count = 0;
	char text[100];
	time_t now = time(NULL);
	struct tm *t = localtime(&now);
	int i;

	if( argc == 2 ){
		output = fopen( argv[1], "w" );
		if( output == NULL ){
			fprintf( stderr,"Cannot open file %s to write\n", argv[1] );
			return 0;
		}
	}
	else
		output = stdout;

	strftime(text, sizeof(text)-1, "%Y-%m-%d %H:%M:%S", t);

	fprintf( output,"/* This code is generated automatically on %s using MMT-DPI v%s. */", text, mmt_version() );
	fprintf( output,"\n/* If you want to modify something, goto %s */", __FILE__ );

	fprintf( output,"\n #ifndef __MMT_SEC_DPI_H_\n #define __MMT_SEC_DPI_H_");
	fprintf( output,"\n #include <stdint.h>\n #include <stdlib.h>\n #include <string.h>");

	//avoid duplicate from data_types.h
	fprintf( output,"\n\n #ifndef TYPES_DEFS_H" );
	fprintf( output,"\n #define TYPES_DEFS_H" );
	fprintf( output,"\nenum data_types { ");
	for( i=0; i<data_type_count; i++ )
		fprintf( output,"\n\t %s, %s", data_type_name[i*2], data_type_name[i*2+1] );
	fprintf( output,"\n};");
	fprintf( output,"\n #endif //end TYPES_DEFS_H\n" );

	fprintf( output,"\n\n static const char *dpi_data_types_name[] = {" );
	for( i=0; i<data_type_count; i++ )
		fprintf( output,"\n\t \"%s\", %s", data_type_name[i*2], data_type_name[i*2+1] );
	fprintf( output,"\n };\n");

	fprintf( output,"\n struct dpi_attribute{\n\t uint32_t gid; \n\t uint16_t id;\n\t const char *name;\n\t long data_type;};");
	fprintf( output,"\n struct dpi_proto{\n\t uint16_t id;\n\t const char *name;\n\t struct dpi_attribute *attributes;\n\t size_t attributes_count;};");


	fprintf( output,"\n\n static const struct dpi_proto *DPI_PROTO = (struct dpi_proto[]){");

	init_extraction();
	iterate_through_protocols( protocols_iterator, &proto_count );
	close_extraction();

	fprintf( output,"}; //TYPES_DEFS_H\n"); //end of struct


	fprintf( output, "\n #define DPI_PROTO_SIZE %d", proto_count );
	fprintf( output, "\n #define DPI_PROTO_ATT_SIZE %d\n", total_proto_att );

	fprintf( output,"\n #ifndef MMT_CORE_H\n #define MMT_CORE_H");

	fprintf( output, "\n static inline uint32_t get_protocol_id_by_name( const char *name ){");
	fprintf( output, "\n	size_t i;");
	fprintf( output, "\n	for( i=0; i<DPI_PROTO_SIZE; i++ )");
	fprintf( output, "\n	if( DPI_PROTO[i].name == NULL )");
	fprintf( output, "\n	  continue;");
	fprintf( output, "\n	else if( strcmp( name, DPI_PROTO[i].name) == 0 )");
	fprintf( output, "\n	  return DPI_PROTO[i].id;");
	fprintf( output, "\n	return -1;");
	fprintf( output, "\n}");

	fprintf( output, "\n static inline const char* get_protocol_name_by_id( uint32_t p_id ){");
	fprintf( output, "\n	size_t i;");
	fprintf( output, "\n	if( p_id >= DPI_PROTO_SIZE ) return NULL; ");
	fprintf( output, "\n	return DPI_PROTO[ p_id ].name;");
	fprintf( output, "\n}");

	fprintf( output, "\n static inline uint32_t get_attribute_id_by_protocol_id_and_attribute_name( uint32_t p_id, const char*attr_name ){");
	fprintf( output, "\n	size_t i; const struct dpi_proto *proto;");
	fprintf( output, "\n	if( p_id >= DPI_PROTO_SIZE ) return -1; ");
	fprintf( output, "\n	proto = &( DPI_PROTO[ p_id ] );");
	fprintf( output, "\n	for( i=0; i<proto->attributes_count; i++ )");
	fprintf( output, "\n		if( strcmp(attr_name, proto->attributes[i].name) == 0 )");
	fprintf( output, "\n			return proto->attributes[i].id;");
	fprintf( output, "\n	return -1;");
	fprintf( output, "\n}");

	fprintf( output, "\n static inline const char* get_attribute_id_by_protocol_id_and_attribute_id( uint32_t p_id, uint32_t attr_id ){");
	fprintf( output, "\n	size_t i; const struct dpi_proto *proto;");
	fprintf( output, "\n	if( p_id >= DPI_PROTO_SIZE ) return NULL; ");
	fprintf( output, "\n	proto = &( DPI_PROTO[ p_id ] );");
	fprintf( output, "\n	for( i=0; i<proto->attributes_count; i++ )");
	fprintf( output, "\n		if( proto->attributes[i].id == attr_id )");
	fprintf( output, "\n			return proto->attributes[i].name;");
	fprintf( output, "\n	return NULL;");
	fprintf( output, "\n}");

	fprintf( output, "\nstatic inline long get_attribute_data_type( uint32_t p_id, uint32_t a_id ){");
	fprintf( output, "\n	size_t i; const struct dpi_proto *proto;");
	fprintf( output, "\n	if( p_id >= DPI_PROTO_SIZE ) return -1; ");
	fprintf( output, "\n	proto = &( DPI_PROTO[ p_id ] );");
	fprintf( output, "\n	for( i=0; i<proto->attributes_count; i++ )");
	fprintf( output, "\n		if( a_id == proto->attributes[i].id )");
	fprintf( output, "\n			return proto->attributes[i].data_type;");
	fprintf( output, "\n	return -1;");
	fprintf( output, "\n}");

	fprintf( output, "\n#endif //MMT_CORE_H");

	fprintf( output, "\nstatic inline long get_attribute_index( uint32_t p_id, uint32_t a_id ){");
	fprintf( output, "\n	size_t i; const struct dpi_proto *proto;");
	fprintf( output, "\n	if( p_id >= DPI_PROTO_SIZE ) return -1; ");
	fprintf( output, "\n	proto = &( DPI_PROTO[ p_id ] );");
	fprintf( output, "\n	for( i=0; i<proto->attributes_count; i++ )");
	fprintf( output, "\n		if( a_id == proto->attributes[i].id )");
	fprintf( output, "\n			return proto->attributes[i].gid;");
	fprintf( output, "\n	return -1;");
	fprintf( output, "\n}");

	fprintf( output,"\n static inline const char* mmt_version(){");
	fprintf( output,"\n    return \"%s\";", mmt_version() );
	fprintf( output, "\n}");

	fprintf( output, "\n#endif //__MMT_SEC_DPI_H_");

	return (EXIT_SUCCESS);
}

