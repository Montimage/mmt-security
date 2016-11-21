/*
 * main_sec_standalone.c
 *
 *  Created on: 18 oct. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 * Standalone mmt-security application.
 * This application can analyze (1) real-time traffic by monitoring a NIC or (2)
 * traffic saved in a pcap file. The verdicts will be printed to the current screen.
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

#include "mmt_core.h"

#include "dpi/mmt_dpi.h"

#include "lib/mmt_lib.h"
#include "lib/plugin_header.h"
#include "lib/mmt_smp_security.h"


#define MAX_FILENAME_SIZE 256
#define TRACE_FILE 1
#define LIVE_INTERFACE 2
#define SNAP_LEN 65355

static size_t proto_atts_count = 0;
static message_element_t *proto_atts = NULL;

/**
 * Print information of the rules existing.
 */
void print_rules_info(){
	const rule_info_t **rules_arr;
	size_t i, n  = 0;

	n = mmt_sec_get_rules_info( &rules_arr );

	printf("Found %zu rule%s", n, n<=1? ".": "s." );

	for( i=0; i<n; i++ ){
		printf("\n%zu - Rule id: %d", (i+1), rules_arr[i]->id );
		printf("\n\t- type            : %s",  rules_arr[i]->type_string );
		printf("\n\t- description     : %s",  rules_arr[i]->description );
		printf("\n\t- if_satisfied    : %s",  rules_arr[i]->if_satisfied );
		printf("\n\t- if_not_satisfied: %s",  rules_arr[i]->if_not_satisfied );
	}
	printf("\n");
	mmt_mem_free( rules_arr );
}

/**
 * Print verdict to the screen.
 * This function is called each time a verdict being detected.
 */
void print_verdict( const rule_info_t *rule,		//id of rule
		enum verdict_type verdict,
		uint64_t timestamp,  //moment the rule is validated
		uint32_t counter,
		const mmt_array_t *const trace,
		void *user_data ){

	struct timeval now;
	gettimeofday(&now, NULL);

	char *string = convert_execution_trace_to_json_string( trace );

	printf( "{\"timestamp\":%ld.%ld,\"pid\":%"PRIu32",\"verdict\":\"%s\",\"type\":\"%s\",\"cause\":\"%s\",\"history\":%s},\n",
			now.tv_sec, now.tv_usec,
			rule->id, verdict_type_string[verdict],  rule->type_string,  rule->description, string );

	mmt_mem_free( string );
}

void usage(const char * prg_name) {
	fprintf(stderr, "MMT-Security version %s\n", mmt_sec_get_version_info() );
	fprintf(stderr, "%s [<option>]\n", prg_name);
	fprintf(stderr, "Option:\n");
	fprintf(stderr, "\t-t <trace file>: Gives the trace file to analyse.\n");
	fprintf(stderr, "\t-i <interface> : Gives the interface name for live traffic analysis.\n");
	fprintf(stderr, "\t-n <number>    : Number of threads. Default = 2\n");
	fprintf(stderr, "\t-l             : Prints the available rules then exit.\n");
	fprintf(stderr, "\t-h             : Prints this help.\n");
	exit(1);
}

size_t parse_options(int argc, char ** argv, char *filename, int *type, uint16_t *rules_id, size_t *threads_count ) {
	int opt, optcount = 0, x;
	filename[0] = '\0';
	while ((opt = getopt(argc, argv, "t:i:n:lh")) != EOF) {
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
		case 'n':
			optcount++;
			if (optcount < 1) {
				usage(argv[0]);
			}
			x = atoi( optarg );
			if( x >= 0 )
				*threads_count = x;
			else
				usage(argv[0]);

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

/**
 * Convert data encoded in a pcap packet to readable data that is either a double
 * or a string ending by '\0'.
 * This function will create a new memory segment to store its result.
 */
static inline void* _get_data( const ipacket_t *pkt, uint32_t proto_id, uint32_t att_id, int data_type, int *new_type ){
	double number;
	char buffer[100], *new_string = NULL;
	const uint16_t buffer_size = 100;
	uint16_t size;
	void *new_data = NULL;
	uint8_t *data = (uint8_t *) get_attribute_extracted_data( pkt, proto_id, att_id );
	//does not exist data for this proto_id and att_id
	if( data == NULL ) return NULL;

	if( mmt_sec_convert_data( data, data_type, &new_data, new_type ) == 0 )
		return new_data;
	return NULL;

}


/**
 * Convert a pcap packet to a message being understandable by mmt-security.
 * The function returns NULL if the packet contains no interested information.
 * Otherwise it creates a new memory segment to store the result message. One need
 * to use #free_message_t to free the message.
 */
static inline message_t* _get_packet_info( const ipacket_t *pkt ){
	size_t size, i, index;
	bool has_data = NO;
	void *data = NULL;
	int type;
	message_t *msg = mmt_mem_alloc( sizeof ( message_t ) );
	msg->timestamp = mmt_sec_encode_timeval( &pkt->p_hdr->ts );
	msg->counter   = pkt->packet_id;

	//get a list of proto/attributes being used by mmt-security
	msg->elements_count = proto_atts_count;
	msg->elements       = mmt_mem_dup( proto_atts, proto_atts_count * sizeof( message_element_t) );
	for( i=0; i<proto_atts_count; i++ ){
		data = _get_data( pkt, proto_atts[i].proto_id, proto_atts[i].att_id, proto_atts[i].data_type, &type );
		if( data != NULL )
			has_data = YES;

		msg->elements[i].data      = data;
		msg->elements[i].data_type = type;
	}

	//need to free #msg when the packet contains no-interested information
	if( likely( has_data ))
		return msg;

	free_message_t( msg );
	return NULL;
}

/**
 * This function is called by mmt-dpi for each incoming packet containing registered proto/att.
 * It gets interested information from the #ipkacet to a message then sends the
 * message to mmt-security.
 */
int packet_handler( const ipacket_t *ipacket, void *args ) {
	mmt_smp_sec_handler_t *sec_handler = (mmt_smp_sec_handler_t *) args;

	message_t *msg = _get_packet_info( ipacket );

	//if there is no interested information
	//TODO: to check if we still need to send timestamp/counter to mmt-sec?
	if( unlikely( msg == NULL )) return 1;

	mmt_smp_sec_process( sec_handler, msg );

	//need to free #msg
	free_message_t( msg );
	return 0;
}

void live_capture_callback( u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data ){
	mmt_handler_t *mmt = (mmt_handler_t*)user;
	struct pkthdr header;
	header.ts     = p_pkthdr->ts;
	header.caplen = p_pkthdr->caplen;
	header.len    = p_pkthdr->len;
	if (!packet_process( mmt, &header, data )) {
		fprintf(stderr, "Packet data extraction failure.\n");
	}
}

static mmt_smp_sec_handler_t *mmt_smp_sec_handler = NULL;
static const rule_info_t **rules_arr = NULL;
static pcap_t *pcap;


void signal_handler(int signal_type) {
	static volatile int times_counter = 0;
	struct pcap_stat pcs; /* packet capture filter stats */

	if( times_counter >= 1 ) exit( signal_type );

	mmt_info( "Interrupted by signal %d", signal_type );

	if( signal_type == SIGINT ){
		mmt_info("Releasing resource ... (press Ctrl+c again to exit immediately)");
		signal(SIGINT, signal_handler);
	}
	else if( signal_type == SIGSEGV ){
		mmt_print_execution_trace();
		exit( signal_type );
	}

	if( times_counter ==  0 ){

		pcap_breakloop( pcap );

		if (pcap_stats(pcap, &pcs) < 0) {
			(void) fprintf(stderr, "pcap_stats: %s\n", pcap_geterr( pcap ));
		}else{
			(void) fprintf(stderr, "\n%12d packets received by filter\n", pcs.ps_recv);
			(void) fprintf(stderr, "%12d packets dropped by kernel (%3.2f%%)\n", pcs.ps_drop, pcs.ps_drop * 100.0 / pcs.ps_recv);
			(void) fprintf(stderr, "%12d packets dropped by interface\n", pcs.ps_ifdrop);
			fflush(stderr);
		}

		mmt_mem_free( proto_atts );
		mmt_smp_sec_unregister( mmt_smp_sec_handler, NO );
		mmt_mem_free( rules_arr );
		mmt_mem_print_info();
	}

	times_counter ++;
	exit( signal_type );
}

void register_signals(){
	signal(SIGSEGV, signal_handler);
	signal(SIGINT,  signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGABRT, signal_handler);
}

int main(int argc, char** argv) {
	mmt_handler_t *mmt_dpi_handler;
	char mmt_errbuf[1024];


	const unsigned char *data;
	struct pcap_pkthdr p_pkthdr;
	char errbuf[1024];
	char filename[MAX_FILENAME_SIZE + 1];
	int type;
	size_t threads_count = 2;
	struct pkthdr header;

	size_t i, j, size;
	uint16_t *rules_id_filter;
	const proto_attribute_t **p_atts;

	parse_options( argc, argv, filename, &type, rules_id_filter, &threads_count );

	register_signals();

	//get all available rules
	size = mmt_sec_get_rules_info( &rules_arr );
	//init mmt-sec to verify the rules
	mmt_smp_sec_handler = mmt_smp_sec_register( rules_arr, size, threads_count, print_verdict, NULL );

	//init mmt_dpi extraction
	init_extraction();
	//Initialize dpi handler
	mmt_dpi_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
	if (!mmt_dpi_handler) { /* pcap error ? */
		fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
		return EXIT_FAILURE;
	}

	//register protocols and their attributes using by mmt-sec
	size = mmt_smp_sec_get_unique_protocol_attributes( mmt_smp_sec_handler, &p_atts );
	proto_atts_count = size;

	proto_atts = mmt_mem_alloc( size * sizeof( message_element_t ));
	for( i=0; i<size; i++ ){
		//mmt_debug( "Registered attribute to extract: %s.%s", proto_atts[i]->proto, proto_atts[i]->att );
		register_extraction_attribute( mmt_dpi_handler, p_atts[i]->proto_id, p_atts[i]->att_id );

		proto_atts[i].proto_id  = p_atts[i]->proto_id;
		proto_atts[i].att_id    = p_atts[i]->att_id;
		proto_atts[i].data_type = get_attribute_data_type( p_atts[i]->proto_id, p_atts[i]->att_id );
	}

	//Register a packet handler, it will be called for every processed packet
	register_packet_handler(mmt_dpi_handler, 1, packet_handler, (void *)mmt_smp_sec_handler );

	if (type == TRACE_FILE) {
		mmt_info("Analyzing pcap file %s", filename );
		pcap = pcap_open_offline(filename, errbuf); // open offline trace
		if (!pcap) { /* pcap error ? */
			mmt_log(ERROR, "pcap_open failed for the following reason: %s\n", errbuf);
			return EXIT_FAILURE;
		}
		while ((data = pcap_next(pcap, &p_pkthdr)) ) {
			header.ts     = p_pkthdr.ts;
			header.caplen = p_pkthdr.caplen;
			header.len    = p_pkthdr.len;
			if (!packet_process(mmt_dpi_handler, &header, data)) {
				mmt_log(ERROR, "Packet data extraction failure.\n");
			}
		}

		mmt_smp_sec_stop( mmt_smp_sec_handler, NO );
	} else {
		mmt_info("Listening on interface %s", filename );

		pcap = pcap_create( filename, errbuf);
		if (pcap == NULL) {
			fprintf(stderr, "Couldn't open device %s\n", errbuf);
			exit( EXIT_FAILURE );
		}
		pcap_set_snaplen(pcap, SNAP_LEN);
		pcap_set_promisc(pcap, 1);
		pcap_set_timeout(pcap, 0);
		pcap_set_buffer_size(pcap, 100*1000*1000);
		pcap_activate(pcap);

		(void)pcap_loop( pcap, -1, &live_capture_callback, (u_char*)mmt_dpi_handler );
	}

	//free resources using by mmt-dpi
	mmt_close_handler(mmt_dpi_handler);
	close_extraction();

	//free resources using by libpcap
	pcap_close(pcap);

	//free resources using by mmt-sec
	mmt_smp_sec_unregister( mmt_smp_sec_handler, NO );
	mmt_mem_free( rules_arr );
	mmt_mem_free( proto_atts );
	//print info about memory using by mmt-sec
	//mmt_mem_print_info();

	return EXIT_SUCCESS;
}

