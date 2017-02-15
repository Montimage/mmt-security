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
#include "lib/verdict_printer.h"

#define MAX_RULE_MASK_SIZE 100000
#define MAX_FILENAME_SIZE 500
#define TRACE_FILE 1
#define LIVE_INTERFACE 2
#define SNAP_LEN 65355

static size_t proto_atts_count       = 0;
static message_element_t *proto_atts = NULL;
//Statistic
static size_t total_received_reports = 0;

static mmt_sec_callback _print_output = NULL;

static const rule_info_t **rules_arr = NULL;
static pcap_t *pcap;

typedef struct _sec_handler_struct{
	void *handler;

	void (*process_fn)( const void *, message_t *);

	int threads_count;
}_sec_handler_t;

static _sec_handler_t _sec_handler;

void usage(const char * prg_name) {
	fprintf(stderr, "MMT-Security version %s using DPI version %s\n", mmt_sec_get_version_info(), mmt_version() );
	fprintf(stderr, "%s [<option>]\n", prg_name);
	fprintf(stderr, "Option:\n");
	fprintf(stderr, "\t-t <trace file>: Gives the trace file to analyse.\n");
	fprintf(stderr, "\t-i <interface> : Gives the interface name for live traffic analysis.\n");
	fprintf(stderr, "\t-c <string>    : Gives the range of logical cores to run on, e.g., \"1,3-8,16\"\n");
	fprintf(stderr, "\t-m <string>    : Attributes special rules to special threads e.g., \"(1:10-13)(2:50)(4:1007-1010)\"\n");
	fprintf(stderr, "\t-f <string>    : Output results to file, e.g., \"/home/tata/:5\" => output to folder /home/tata and each file contains reports during 5 seconds \n");
	fprintf(stderr, "\t-r <string>    : Output results to redis, e.g., \"localhost:6379\"\n");
	fprintf(stderr, "\t-v             : Verbose.\n");
	fprintf(stderr, "\t-l             : Prints the available rules then exit.\n");
	fprintf(stderr, "\t-h             : Prints this help.\n");
	exit(1);
}

size_t parse_options(int argc, char ** argv, char *filename, int *type, uint16_t *rules_id, size_t *threads_count, uint32_t **core_mask, char *rule_mask, bool *verbose ) {
	int opt, optcount = 0, x;
	char file_string[MAX_FILENAME_SIZE]  = {0};
	char redis_string[MAX_FILENAME_SIZE] = {0};
	*verbose = NO;
	filename[0] = '\0';
	while ((opt = getopt(argc, argv, "t:i:f:r:c:m:lhv")) != EOF) {
		switch (opt) {
		case 't':
			optcount++;
			strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
			*type = TRACE_FILE;
			break;
		case 'c':
			optcount++;
			*threads_count = expand_number_range( optarg, core_mask );
			if( *threads_count == 0 )
				usage(argv[0]);
			break;
		case 'i':
			optcount++;
			strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
			*type = LIVE_INTERFACE;
			break;
		case 'f':
			optcount++;
			strncpy((char *) file_string, optarg, MAX_FILENAME_SIZE);
			break;
		case 'm':
			optcount++;
			strncpy( rule_mask, optarg, MAX_RULE_MASK_SIZE );
			break;
		case 'r':
			optcount++;
			strncpy((char *) redis_string, optarg, MAX_FILENAME_SIZE);
			break;
		case 'l':
			mmt_sec_print_rules_info();
			exit( 0 );
		case 'v':
			optcount++;
			*verbose = YES;
			break;
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

	//do not need output
	if( file_string[0] == '\0' &&  redis_string[0] == '\0' )
		_print_output = NULL;
	else{
		_print_output = mmt_sec_print_verdict;

		verdict_printer_init( file_string, redis_string );
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
	uint32_t *data_len;
	uint8_t *data = (uint8_t *) get_attribute_extracted_data( pkt, proto_id, att_id );
	//does not exist data for this proto_id and att_id
	if( data == NULL ) return NULL;

	//tcp.p_payload
	if( proto_id == 354 && att_id == 4098 ){
		data_len = (uint32_t *)get_attribute_extracted_data( pkt, 354, 23 );
		if( data_len == NULL )
			return NULL;

		*new_type = VOID;
		return mmt_mem_dup( data, *data_len );
	}

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
	message_t *msg = create_message_t( proto_atts_count );
	msg->timestamp = mmt_sec_encode_timeval( &pkt->p_hdr->ts );
	msg->counter   = pkt->packet_id;

	//get a list of proto/attributes being used by mmt-security
	for( i=0; i<proto_atts_count; i++ ){
		data = _get_data( pkt, proto_atts[i].proto_id, proto_atts[i].att_id, proto_atts[i].data_type, &type );
		if( data != NULL )
			has_data = YES;

		msg->elements[i].data      = data;
		msg->elements[i].data_type = type;
		msg->elements[i].att_id    = proto_atts[i].att_id;
		msg->elements[i].proto_id  = proto_atts[i].proto_id;
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
	message_t *msg = _get_packet_info( ipacket );

	//if there is no interested information
	//TODO: to check if we still need to send timestamp/counter to mmt-sec?
	if( unlikely( msg == NULL )) return 1;

	_sec_handler.process_fn( _sec_handler.handler, msg );

	total_received_reports ++;

	return 1;
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


static inline void termination(){
	struct pcap_stat pcs; /* packet capture filter stats */
	size_t alerts_count;

	pcap_breakloop( pcap );

	if( _sec_handler.threads_count > 1 )
		alerts_count = mmt_smp_sec_unregister( _sec_handler.handler, NO );
	else
		alerts_count = mmt_sec_unregister( _sec_handler.handler );

	if (pcap_stats(pcap, &pcs) < 0) {
//		(void) fprintf(stderr, "pcap_stats: %s\n", pcap_geterr( pcap ));//Statistics aren't available from savefiles
	}else{
		(void) fprintf(stderr, "\n%12d packets received by filter\n", pcs.ps_recv);
		(void) fprintf(stderr, "%12d packets dropped by interface\n", pcs.ps_ifdrop);
		(void) fprintf(stderr, "%12d packets dropped by kernel (%3.2f%%)\n", pcs.ps_drop, pcs.ps_drop * 100.0 / pcs.ps_recv);
		fflush(stderr);
	}

	fprintf(stderr, "%12zu reports received\n", total_received_reports );
	fprintf(stderr, "%12"PRIu64" alerts generated\n", alerts_count );

	if( _print_output != NULL )
		verdict_printer_free();

	mmt_mem_free( proto_atts );

	mmt_mem_free( rules_arr );
}

void signal_handler_seg(int signal_type) {
	mmt_error( "Interrupted by signal %d", signal_type );
	mmt_print_execution_trace();
	usleep( 50 );
	exit( signal_type );
}

void signal_handler(int signal_type) {
	static volatile int times_counter = 0;

	if( times_counter >= 1 ) exit( signal_type );
	times_counter ++;

	mmt_error( "Interrupted by signal %d", signal_type );

	if( signal_type == SIGINT ){
		mmt_error("Releasing resource ... (press Ctrl+c again to exit immediately)");
		signal(SIGINT, signal_handler);
	}
	termination();
	exit( signal_type );
}



void register_signals(){
//#ifndef DEBUG_MODE
	signal(SIGSEGV, signal_handler_seg );
//#endif
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
	size_t core_size;
	uint32_t *core_mask = NULL;
	int type;
	size_t threads_count = 1;
	bool verbose;
	struct pkthdr header;
	char rule_mask[ MAX_RULE_MASK_SIZE ];
	size_t i, j, size;
	uint16_t *rules_id_filter;
	const proto_attribute_t **p_atts;

	parse_options( argc, argv, filename, &type, rules_id_filter, &threads_count, &core_mask, rule_mask, &verbose );

	register_signals();

	//get all available rules
	size = mmt_sec_get_rules_info( &rules_arr );

	_sec_handler.threads_count = threads_count;

	//init mmt-sec to verify the rules
	if( _sec_handler.threads_count == 1 ){
		_sec_handler.handler    = mmt_sec_register( rules_arr, size, _print_output, NULL );
		_sec_handler.process_fn = &mmt_sec_process;
		size = mmt_sec_get_unique_protocol_attributes( _sec_handler.handler, &p_atts );
	}else if( _sec_handler.threads_count > 1 ){
		_sec_handler.handler    = mmt_smp_sec_register( rules_arr, size, _sec_handler.threads_count - 1, core_mask, rule_mask, verbose, _print_output, NULL );
		_sec_handler.process_fn = &mmt_smp_sec_process;
		size = mmt_smp_sec_get_unique_protocol_attributes( _sec_handler.handler, &p_atts );
	}else{
		usage( argv[0] );
	}

	if( core_mask != NULL ){
		//main thread on the last core
		if( move_the_current_thread_to_a_processor( core_mask[ threads_count - 1 ], -15 ) )
			mmt_warn("Cannot set affinity of process %d on lcore %d", gettid(), core_mask[ threads_count - 1 ] );

		mmt_mem_free( core_mask );
	}
	//init mmt_dpi extraction
	init_extraction();
	//Initialize dpi handler
	mmt_dpi_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
	if (!mmt_dpi_handler) { /* pcap error ? */
		fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
		return EXIT_FAILURE;
	}

	//register protocols and their attributes using by mmt-sec
	proto_atts_count = size;

	proto_atts = mmt_mem_alloc( size * sizeof( message_element_t ));
	for( i=0; i<size; i++ ){
		//mmt_debug( "Registered attribute to extract: %s.%s", proto_atts[i]->proto, proto_atts[i]->att );
		register_extraction_attribute( mmt_dpi_handler, p_atts[i]->proto_id, p_atts[i]->att_id );

		//tcp.p_payload
		if( p_atts[i]->proto_id == 354 && p_atts[i]->att_id == 4098)
			//tcp.payload_len
			register_extraction_attribute( mmt_dpi_handler, 354, 23 );

		proto_atts[i].proto_id  = p_atts[i]->proto_id;
		proto_atts[i].att_id    = p_atts[i]->att_id;
		proto_atts[i].data_type = get_attribute_data_type( p_atts[i]->proto_id, p_atts[i]->att_id );
	}

	//Register a packet handler, it will be called for every processed packet
	register_packet_handler(mmt_dpi_handler, 1, packet_handler, NULL );

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

	termination();

	return EXIT_SUCCESS;
}

