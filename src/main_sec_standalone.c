/*
 * main_sec_standalone.c
 *
 *  Created on: 18 oct. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 * Standalone mmt-security application.
 */
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>

#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif


#include "mmt_core.h"

#include "lib/mmt_lib.h"
#include "lib/plugin_header.h"
#include "lib/mmt_security.h"

#define MAX_FILENAME_SIZE 256
#define TRACE_FILE 1
#define LIVE_INTERFACE 2
#define MTU_BIG (16 * 1024)

void print_rules_info(){
	const rule_info_t **rules_arr;
	size_t i, n  = 0;

	n = load_mmt_sec_rules( &rules_arr );

	printf("Found %zu rule%s", n, n<=1? ".": "s." );

	for( i=0; i<n; i++ ){
		printf("\n%zu - Rule id: %d", (i+1), rules_arr[i]->id );
		printf("\n\t- type            : %s",  rules_arr[i]->type_string );
		printf("\n\t- description     : %s",  rules_arr[i]->description );
		printf("\n\t- if_satisfied    : %s",  rules_arr[i]->if_satisfied );
		printf("\n\t- if_not_satisfied: %s",  rules_arr[i]->if_not_satisfied );
	}
	printf("\n");
	mmt_free( rules_arr );
}

void print_verdict( const rule_info_t *rule,		//id of rule
		enum verdict_type verdict,
		uint64_t timestamp,  //moment the rule is validated
		uint32_t counter,
		const mmt_map_t *trace,
		void *user_data ){
	char *string = convert_execution_trace_to_json_string( trace );
	mmt_debug( "Rule %"PRIu32": %s: %s \n%s\n %s", rule->id, rule->type_string, verdict_type_string[verdict], rule->description, string );
	mmt_free( string );
}

void usage(const char * prg_name) {
	fprintf(stderr, "%s [<option>]\n", prg_name);
	fprintf(stderr, "Option:\n");
	fprintf(stderr, "\t-t <trace file>: Gives the trace file to analyse.\n");
	fprintf(stderr, "\t-i <interface> : Gives the interface name for live traffic analysis.\n");
	fprintf(stderr, "\t-l             : Prints the available rules then exit.\n");
	fprintf(stderr, "\t-h             : Prints this help.\n");
	exit(1);
}

size_t parse_options(int argc, char ** argv, char *filename, int *type, uint16_t *rules_id) {
	int opt, optcount = 0;
	filename[0] = '\0';
	while ((opt = getopt(argc, argv, "t:i:lh")) != EOF) {
		switch (opt) {
		case 't':
			optcount++;
			if (optcount > 1) {
				usage(argv[0]);
			}
			strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
			*type = TRACE_FILE;
			break;
		case 'i':
			optcount++;
			if (optcount > 1) {
				usage(argv[0]);
			}
			strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
			*type = LIVE_INTERFACE;
			break;
		case 'l':
			print_rules_info();
			exit( 0 );
		case 'h':
		default:
			usage(argv[0]);
		}
	}

	if (filename == NULL || strcmp(filename, "") == 0) {
		if (*type == TRACE_FILE) {
			fprintf(stderr, "Missing trace file name\n");
		}
		if (*type == LIVE_INTERFACE) {
			fprintf(stderr, "Missing network interface name\n");
		}
		usage(argv[0]);
	}
	return 0;
}

static inline void* _get_data( const ipacket_t *pkt, const proto_attribute_t *me ){
	double number;
	char *string;
	void *data = get_attribute_extracted_data( pkt, me->proto_id, me->att_id );
	int type   = get_attribute_data_type( me->proto_id, me->att_id );
	switch( type ){
		 case MMT_UNDEFINED_TYPE: /**< no type constant value */
			 return NULL;
		 case MMT_DATA_CHAR: /**< 1 character constant value */
	    case MMT_U8_DATA: /**< unsigned 1-byte constant value */
	   	 	number = *(uint8_t *) data;
	   	 	break;
	    case MMT_U16_DATA: /**< unsigned 2-bytes constant value */
	   	 number = *(uint16_t *) data;
	   	 break;
	    case MMT_U32_DATA: /**< unsigned 4-bytes constant value */
	   	 number = *(uint32_t *) data;
	   	 break;
	    case MMT_U64_DATA: /**< unsigned 8-bytes constant value */
	   	 number = *(uint64_t *) data;
	   	 break;
	    case MMT_DATA_FLOAT: /**< float constant value */
	   	 number = *(float *) data;
			 break;
	    case MMT_DATA_POINTER: /**< pointer constant value (size is void *) */
	   	 return data;
	   	 break;
	    case MMT_DATA_MAC_ADDR: /**< ethernet mac address constant value */
	    case MMT_DATA_IP_NET: /**< ip network address constant value */
	    case MMT_DATA_IP_ADDR: /**< ip address constant value */
	    case MMT_DATA_IP6_ADDR: /**< ip6 address constant value */
	    case MMT_DATA_PATH: /**< protocol path constant value */
	    case MMT_DATA_TIMEVAL: /**< number of seconds and microseconds constant value */
	    case MMT_DATA_BUFFER: /**< binary buffer content */
	    case MMT_DATA_PORT: /**< tcp/udp port constant value */
	    case MMT_DATA_POINT: /**< point constant value */
	    case MMT_DATA_PORT_RANGE: /**< tcp/udp port range constant value */
	    case MMT_DATA_DATE: /**< date constant value */
	    case MMT_DATA_TIMEARG: /**< time argument constant value */
	    case MMT_DATA_STRING_INDEX: /**< string index constant value (an association between a string and an integer) */
	    case MMT_DATA_LAYERID: /**< Layer ID value */
	    case MMT_DATA_FILTER_STATE: /**< (filter_id: filter_state) */
	    case MMT_DATA_PARENT: /**< (filter_id: filter_state) */
	    case MMT_STATS: /**< pointer to MMT Protocol statistics */
	    case MMT_BINARY_DATA: /**< binary constant value */
	    case MMT_BINARY_VAR_DATA: /**< binary constant value with variable size given by function getExtractionDataSizeByProtocolAndFieldIds */
	    case MMT_STRING_DATA: /**< text string data constant value. Len plus data. Data is expected to be '\0' terminated and maximum BINARY_64DATA_LEN long */
	    case MMT_STRING_LONG_DATA: /**< text string data constant value. Len plus data. Data is expected to be '\0' terminated and maximum STRING_DATA_LEN long */
	    case MMT_HEADER_LINE: /**< string pointer value with a variable size. The string is not necessary null terminating */
	    case MMT_GENERIC_HEADER_LINE: /**< structure representing an RFC2822 header line with null terminating field and value elements. */
	    case MMT_STRING_DATA_POINTER: /**< pointer constant value (size is void *). The data pointed to is of type string with null terminating character included */
	   	 break;
	}
	if( me->data_type == 0 )//NUMERIC )
		return mmt_mem_dup( &number, sizeof( double ));
	return NULL;
}

static inline message_t* _get_packet_info( const ipacket_t *pkt, const mmt_sec_handler_t *handler ){
	size_t size, i;
	const proto_attribute_t **arr;
	bool has_data = NO;
	void *data;
	message_t *msg = mmt_malloc( sizeof ( message_t ) );
	msg->timestamp = mmt_sec_encode_timeval( &pkt->p_hdr->ts );
	msg->counter   = pkt->packet_id;

	size = mmt_sec_get_unique_protocol_attributes( handler, &arr );

	msg->elements_count = size;
	msg->elements       = mmt_malloc( sizeof( message_element_t ) * size );
	for( i=0; i<size; i++ ){
		data = _get_data( pkt, arr[i] );
		if( data != NULL )
			has_data = YES;
		msg->elements[i].proto_id = arr[i]->proto_id;
		msg->elements[i].att_id   = arr[i]->att_id;
		msg->elements[i].data     = NULL;//data;

	}

	if( !has_data ){
		mmt_free( msg->elements );
		mmt_free( msg );
		return NULL;
	}

	return msg;
}

int packet_handler( const ipacket_t *ipacket, void *args ) {
	mmt_sec_handler_t *sec_handler = (mmt_sec_handler_t *) args;
	message_t *msg = _get_packet_info( ipacket, sec_handler );

	if( msg == NULL ) return 1;

	mmt_sec_process( sec_handler, msg );

	mmt_free( msg->elements );
	mmt_free( msg );
	return 0;
}

void live_capture_callback( u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data )
{
	mmt_handler_t *mmt = (mmt_handler_t*)user;
	struct pkthdr header;
	header.ts     = p_pkthdr->ts;
	header.caplen = p_pkthdr->caplen;
	header.len    = p_pkthdr->len;
	if (!packet_process( mmt, &header, data )) {
		fprintf(stderr, "Packet data extraction failure.\n");
	}
}

void signal_handler(int signal_type) {
	exit( signal_type );
}

int main(int argc, char** argv) {
	mmt_handler_t *mmt_dpi_handler;
	char mmt_errbuf[1024];

	pcap_t *pcap;
	const unsigned char *data;
	struct pcap_pkthdr p_pkthdr;
	char errbuf[1024];
	char filename[MAX_FILENAME_SIZE + 1];
	int type;

	struct pkthdr header;

	const rule_info_t **rules_arr;
	size_t i, j, size;
	mmt_sec_handler_t *mmt_sec_handler = NULL;
	uint16_t *rules_id_filter;
	const proto_attribute_t **proto_atts;

	parse_options( argc, argv, filename, &type, rules_id_filter );

	signal(SIGINT,  signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGABRT, signal_handler);

	size = load_mmt_sec_rules( &rules_arr );
	mmt_sec_handler = mmt_sec_register( rules_arr, size, print_verdict, NULL );

	//init mmt_dpi extraction
	init_extraction();

	//Initialize dpi handler
	mmt_dpi_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
	if (!mmt_dpi_handler) { /* pcap error ? */
		fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
		return EXIT_FAILURE;
	}

	//register protocols and their attributes using by mmt-sec
	size = mmt_sec_get_unique_protocol_attributes( mmt_sec_handler, &proto_atts );
	for( i=0; i<size; i++ ){
		mmt_debug( "Registered attribute to extract: %s.%s", proto_atts[i]->proto, proto_atts[i]->att );
		register_extraction_attribute( mmt_dpi_handler, proto_atts[i]->proto_id, proto_atts[i]->att_id );
	}

	//Register a packet handler, it will be called for every processed packet
	register_packet_handler(mmt_dpi_handler, 1, packet_handler, (void *)mmt_sec_handler );

	if (type == TRACE_FILE) {
		pcap = pcap_open_offline(filename, errbuf); // open offline trace
		if (!pcap) { /* pcap error ? */
			fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
			return EXIT_FAILURE;
		}

		while ((data = pcap_next(pcap, &p_pkthdr))) {
			header.ts     = p_pkthdr.ts;
			header.caplen = p_pkthdr.caplen;
			header.len    = p_pkthdr.len;
			if (!packet_process(mmt_dpi_handler, &header, data)) {
				fprintf(stderr, "Packet data extraction failure.\n");
			}
		}
	} else {
		mmt_info("Listening on interface %s", filename );
		pcap = pcap_open_live(filename, MTU_BIG, 1, 1000, errbuf);
		if (!pcap) {
			fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
			return EXIT_FAILURE;
		}
		(void)pcap_loop( pcap, -1, &live_capture_callback, (u_char*)mmt_dpi_handler );
	}

	mmt_close_handler(mmt_dpi_handler);

	close_extraction();

	pcap_close(pcap);

	mmt_sec_unregister( mmt_sec_handler );
	mmt_free( rules_arr );

	return EXIT_SUCCESS;
}

