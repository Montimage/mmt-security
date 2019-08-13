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

#include "lib/dpi_message_t.h"
#include "lib/mmt_security.h"
#define MAX_RULE_MASK_SIZE 100000
#define MAX_FILENAME_SIZE 500
#define TRACE_FILE 1
#define LIVE_INTERFACE 2
#define SNAP_LEN 65355

//Statistic
static size_t total_received_reports = 0;

static mmt_sec_callback _print_output = NULL;

static size_t proto_atts_count        = 0;
proto_attribute_t const *const*proto_atts  = NULL;

static pcap_t *pcap;

//handler of MMT-SEC
static mmt_sec_handler_t *sec_handler  = NULL;

//handler of MMT-DPI
static mmt_handler_t *mmt_dpi_handler = NULL;

void usage(const char * prg_name) {
	fprintf(stderr, "MMT-Security version %s using DPI version %s\n", mmt_sec_get_version_info(), mmt_version() );
	fprintf(stderr, "\nUsage: %s [<option>]\n", prg_name);
	fprintf(stderr, "Option:\n");
	fprintf(stderr, "\t-t <trace file>: Gives the trace file to analyse.\n");
	fprintf(stderr, "\t-i <interface> : Gives the interface name for live traffic analysis.\n");
	fprintf(stderr, "\t-c <string>    : Gives the range of logical cores to run on, e.g., \"1,3-8,16\"\n");
	fprintf(stderr, "\t-x <string>    : Gives the range of rules id to be excluded, e.g., \"99,107-1010\".\n");
	fprintf(stderr, "\t-m <string>    : Attributes special rules to special threads using format (lcore:range) e.g., \"(1:1-8,10-13)(2:50)(4:1007-1010)\".\n");
	fprintf(stderr, "\t-f <string>    : Output results to file, e.g., \"/home/tata/:5\" => output to folder /home/tata and each file contains reports during 5 seconds \n");
	fprintf(stderr, "\t-r <string>    : Output results to redis, e.g., \"localhost:6379\"\n");
	fprintf(stderr, "\t-g             : Ignore the rest of a flow when an alert was detetected on the flow.\n");
	fprintf(stderr, "\t-v             : Verbose.\n");
	fprintf(stderr, "\t-l             : Prints the available rules then exit.\n");
	fprintf(stderr, "\t-h             : Prints this help.\n");
	exit(1);
}

size_t parse_options(int argc, char ** argv, char *filename, int *type, uint16_t *rules_id,
		size_t *threads_count, uint32_t **core_mask, char *excludes_rules_mask, char *rule_mask, bool *is_ignore, bool *verbose ) {
	int opt, optcount = 0, x;
	char file_string[MAX_FILENAME_SIZE]  = {0};
	char redis_string[MAX_FILENAME_SIZE] = {0};

	excludes_rules_mask[0] = '\0';
	rule_mask[0]           = '\0';

	*verbose = NO;
	*is_ignore = NO;
	filename[0] = '\0';
	while ((opt = getopt(argc, argv, "t:i:f:r:c:m:x:lhvg")) != EOF) {
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
		case 'x':
			optcount++;
			strncpy((char *) excludes_rules_mask, optarg, MAX_FILENAME_SIZE);
			break;
		case 'l':
			mmt_sec_init( excludes_rules_mask );
			mmt_sec_print_rules_info();
			mmt_sec_close();
			exit( 0 );
		case 'g':
			optcount++;
			*is_ignore = true;
			//Do nothing. Keep for future use.
			break;
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
 * Convert a pcap packet to a message being understandable by mmt-security.
 * The function returns NULL if the packet contains no interested information.
 * Otherwise it creates a new memory segment to store the result message. One need
 * to use #free_message_t to free the message.
 */
static inline message_t* _get_packet_info( const ipacket_t *pkt ){
	int i;
	void *data;
	int type;

	message_t *msg = create_message_t();
	msg->timestamp = mmt_sec_encode_timeval( &pkt->p_hdr->ts );
	msg->counter   = pkt->packet_id;
	msg->flow_id   = get_session_id_from_packet( pkt );
	//get a list of proto/attributes being used by mmt-security
	for( i=0; i<proto_atts_count; i++ )
		dpi_message_set_data( pkt, proto_atts[i]->dpi_type, msg, proto_atts[i]->proto_id, proto_atts[i]->att_id );

	if( likely( msg->elements_count ))
		return msg;

	//need to free #msg when the packet contains no-interested information
	free_message_t( msg );
	return NULL;
}


/**
 * Register an attribute of a protocol to MMT-DPI. They are given by their IDs
 * @param proto_id
 * @param att_id
 * @param verbose
 * @return true if it is registered successfully
 * 		   false if it has been registered or it can not be registered
 */
static inline bool _register_proto_att_to_mmt_dpi( uint32_t proto_id, uint32_t att_id, bool verbose ){
	//is it registered?
	if( is_registered_attribute( mmt_dpi_handler, proto_id, att_id ))
		return 0;
	if( register_extraction_attribute( mmt_dpi_handler, proto_id, att_id ) ){
#ifdef DEBUG_MODE
		if( verbose )
			mmt_debug( "Registered attribute to extract: %"PRIu32".%"PRIu32, proto_id, att_id );
#endif
		return 1;
	}
	return 0;
}

/**
 * update of list of unique att_protos and register them to MMT-DPI
 * @return number of att_protos being registered
 */
static inline size_t _update_and_register_protocols_attributes_to_extract( bool verbose ){
	int i;
	size_t ret = 0;
	proto_atts_count = mmt_sec_get_unique_protocol_attributes( & proto_atts );

	for( i=0; i<proto_atts_count; i++ ){

		ret += _register_proto_att_to_mmt_dpi( proto_atts[i]->proto_id, proto_atts[i]->att_id, verbose  );

		//tcp.p_payload => need payload_len
		if( proto_atts[i]->proto_id == PROTO_TCP && proto_atts[i]->att_id == PROTO_PAYLOAD ){
			//tcp.payload_len
			ret += _register_proto_att_to_mmt_dpi( PROTO_TCP, TCP_PAYLOAD_LEN, verbose );
		}else if( proto_atts[i]->proto_id == PROTO_IP && proto_atts[i]->att_id == IP_OPTS){
			ret += _register_proto_att_to_mmt_dpi( PROTO_IP, IP_HEADER_LEN, verbose );
		}
	}
	return ret;
}

#ifdef MODULE_ADD_OR_RM_RULES_RUNTIME
static inline void _print_add_rm_rules_instruction(){
	mmt_info("During runtime, user can add or remove some rules using the following commands:\n%s\n%s",
		" - to add new rules: add rule_mask, for example: add (1:1-3)(2:4-6)",
		" - to remove existing rules: rm rule_range, for example: rm  1-3");
}

/**
 * Add rules to process and update DPI to extract the corresponding protos/atts
 * @param rules_mask
 * @return number of rules being added
 */
static inline size_t _add_rules( const char* rules_mask ){
	size_t ret = mmt_sec_add_rules(rules_mask);
	//no new rules being added
	if( ret == 0 )
		return ret;

	//register the new proto_atts if need
	size_t count = _update_and_register_protocols_attributes_to_extract( false );
	mmt_debug( "Registered %zu new proto_atts", count );

	return ret;
}


static inline size_t _remove_rules( size_t rules_count, const uint32_t *rules_ids_array ){
	proto_attribute_t const*const* old_proto_atts;
	proto_attribute_t const*const* new_proto_atts;
	size_t old_proto_atts_count, new_proto_atts_count;
	size_t i, j;

	old_proto_atts_count = mmt_sec_get_unique_protocol_attributes( & old_proto_atts );

	size_t ret = mmt_sec_remove_rules( rules_count, rules_ids_array );
	//no rules being removed ???
	if( ret == 0 )
		return ret;

	new_proto_atts_count = mmt_sec_get_unique_protocol_attributes( & new_proto_atts );

	//set of proto_atts does not change after removing some rules => donot need to unregister any proto_att
	if( old_proto_atts_count == new_proto_atts_count )
		return ret;

	//unregister the att_protos of rules being removed
	//for each old protol_att
	for( i=0; i<old_proto_atts_count; i++ ){
		for( j=0; j<new_proto_atts_count; j++ )
			if( old_proto_atts[i]->proto_id == new_proto_atts[i]->proto_id &&
				 old_proto_atts[i]->att_id == new_proto_atts[i]->att_id )
				break; //this proto_att is still needed
		//
		if( j <= new_proto_atts_count )
			continue;
		//unregister this old proto_att
		unregister_extraction_attribute(mmt_dpi_handler, old_proto_atts[i]->proto_id, old_proto_atts[i]->att_id );
		mmt_debug("Unregistered from mmt-dpi: %"PRIu32".%"PRIu32" (%s,%s)",
				old_proto_atts[i]->proto_id, old_proto_atts[i]->att_id,
				old_proto_atts[i]->proto, old_proto_atts[i]->att );
	}
	return ret;
}

/**
 * This has to be called before any stdin input function.
 * When I used std::cin before using this function, it never returned true again.
 * @return true if user press some keys ended by Enter
 */
static inline bool _is_user_press_keys(){
    struct timeval tv;
    fd_set fds;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds); //add stdin to fsd, STDIN_FILENO is 0
    select(STDIN_FILENO+1, &fds, NULL, NULL, &tv);
    return ( FD_ISSET(STDIN_FILENO, &fds) != 0 );
}

void _add_or_remove_rules_if_need(){
	const int len = 1000;

	char buffer[ 1000 ], *c;
	size_t count;
	uint32_t *rules_id_to_rm_set;
	//if user does not press any keys
	if( _is_user_press_keys() == false )
		return;

	//get user's string
	if( !fgets( buffer, len, stdin) )
		return;

	//as fgets add EOF or EOL at the end of buffer => we need to remove these special characters
	c = buffer;
	while( *c != '\0' ){
		if( *c == EOF || *c == '\n' ){
			*c = '\0';
			break;
		}
		c++;
	}


	if( buffer[0] == '\0' )
		return;

	//add xxxx
	if( buffer[0] == 'a' && buffer[1] == 'd' && buffer[2] == 'd'  && buffer[3] == ' ' ){
		mmt_info( "Added totally %zu rule(s)", _add_rules( &buffer[4] ));
		return;
	}else //rm xxx
		if( buffer[0] == 'r' && buffer[1] == 'm'  && buffer[2] == ' ' ){
			count = expand_number_range( &buffer[3], &rules_id_to_rm_set );
			if( count > 0 ){
				count = _remove_rules( count, rules_id_to_rm_set);
			}
			mmt_info( "Removed totally %zu rule(s)", count);

			//free memory allocated by expand_number_range
			mmt_mem_free( rules_id_to_rm_set );
			return;
	}

	mmt_warn("Unknown command \"%s\"", buffer );
	_print_add_rm_rules_instruction();
}
/* Returns an integer in the range [1, n].
 *
 * Uses rand(), and so is affected-by/affects the same seed.
 */
static inline int _rand_int(unsigned int n) {
  if ((n - 1) == RAND_MAX) {
    return rand();
  } else {
    // Chop off all of the values that would cause skew...
    long end = RAND_MAX / n; // truncate skew
    end *= n;

    // ... and ignore results from rand() that fall above that limit.
    // (Worst case the loop condition should succeed 50% of the time,
    // so we can expect to bail out of this loop pretty quickly.)
    int r;
    while ((r = rand()) >= end);

    return r % n + 1;
  }
}

static inline bool _rand_bool(){
	return (_rand_int( 10 ) > 5);
}
#else
#define _add_or_remove_rules_if_need()
#define _print_add_rm_rules_instruction()
#endif



static bool can_ignore_remain_flow = false;
/**
 * This function is called by mmt-dpi for each incoming packet containing registered proto/att.
 * It gets interested information from the #ipkacet to a message then sends the
 * message to mmt-security.
 */
int packet_handler( const ipacket_t *ipacket, void *args ) {
	uint32_t rm_rules_arr[50];
	char string[500], *ch = string;
	int i;

	mmt_sec_handler_t *handler = (mmt_sec_handler_t *)args;

	uint64_t flow_id = get_session_id_from_packet( ipacket );

	if( can_ignore_remain_flow && mmt_sec_is_ignore_remain_flow(handler, flow_id) )
		return 0;

	message_t *msg = _get_packet_info( ipacket );

	//if there is no interested information
	//TODO: to check if we still need to send timestamp/counter to mmt-sec?
	if( unlikely( msg == NULL )) return 1;

	mmt_sec_process( handler, msg );

//TODO: remve this block
//#ifdef MODULE_ADD_OR_RM_RULES_RUNTIME
//	if( total_received_reports == 1000 ){
//		mmt_debug("Add %zu rules", _add_rules("(1:33,32,34)"));
//		//need to add/rm or not?
//		if( _rand_bool() ){
//			printf("\n%zu\n", total_received_reports );
//			//add or rm rules?
//			if( _rand_bool() ){
//				//rm random rules ID
//				int nb_rules_to_rm = _rand_int( 5 );
//				for( i=0; i<nb_rules_to_rm; i++ )
//					rm_rules_arr[i] = _rand_int( 50 );
//				mmt_sec_remove_rules( nb_rules_to_rm, rm_rules_arr );
//			}else{
//				//add
//				int nb_rules_to_add = _rand_int( 5 );
//				ch = string;
//				ch += sprintf(string, "(%d:", _rand_int(9) );
//				for( i=0; i<nb_rules_to_add; i++ )
//					ch += sprintf(ch, "%d,", _rand_int( 50 ) );
//				*ch = '\0';
//				*(ch - 1) = ')';
//
//				_add_rules( string );
//
//			}
//		}
//	}
//#endif

	total_received_reports ++;

	return 0;
}

void live_capture_callback( u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data ){
	mmt_handler_t *mmt = (mmt_handler_t*)user;
	struct pkthdr header;

	//allow user to add/rm rules
	_add_or_remove_rules_if_need();

	header.ts     = p_pkthdr->ts;
	header.caplen = p_pkthdr->caplen;
	header.len    = p_pkthdr->len;
	if (!packet_process( mmt, &header, data )) {
		fprintf(stderr, "Packet data extraction failure.\n");
	}
	//printf("."); fflush( stdout );
}


static inline void termination(){
	struct pcap_stat pcs; /* packet capture filter stats */
	size_t alerts_count;

	pcap_breakloop( pcap );

	alerts_count = mmt_sec_unregister( sec_handler );

	if (pcap_stats(pcap, &pcs) < 0) {
//		(void) fprintf(stderr, "pcap_stats: %s\n", pcap_geterr( pcap ));//Statistics aren't available from savefiles
	}else{
		(void) fprintf(stderr, "\n%12d packets received by filter\n", pcs.ps_recv);
		(void) fprintf(stderr, "%12d packets dropped by interface\n", pcs.ps_ifdrop);
		(void) fprintf(stderr, "%12d packets dropped by kernel (%3.2f%%)\n", pcs.ps_drop, pcs.ps_drop * 100.0 / pcs.ps_recv);
		fflush(stderr);
	}

	fprintf(stderr, "%12zu messages received\n", total_received_reports );
	fprintf(stderr, "%12zu alerts generated\n", alerts_count );

	pcap_close( pcap );

	if( _print_output != NULL )
		verdict_printer_free();

	mmt_sec_close();   // close mmt_security
	close_extraction();// close mmt_dpi
}

void signal_handler_seg(int signal_type) {
	mmt_error( "Interrupted by signal %d", signal_type );
	mmt_print_execution_trace();
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
#ifndef DEBUG_MODE
	signal(SIGSEGV, signal_handler_seg );
#endif
	signal(SIGINT,  signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGABRT, signal_handler);
}

int main(int argc, char** argv) {
	char mmt_errbuf[1024];

	const unsigned char *data;
	struct pcap_pkthdr p_pkthdr;
	char errbuf[1024];
	char filename[MAX_FILENAME_SIZE + 1];
	size_t core_size;
	uint32_t *core_mask = NULL;
	int type;
	size_t threads_count = 0;
	bool verbose;
	struct pkthdr header;
	char rule_mask[ MAX_RULE_MASK_SIZE ], excludes_rules_mask[ MAX_RULE_MASK_SIZE ];
	size_t i, j, size;
	uint16_t *rules_id_filter = NULL;

	parse_options( argc, argv, filename, &type, rules_id_filter, &threads_count,
			&core_mask, excludes_rules_mask, rule_mask, &can_ignore_remain_flow, &verbose );

	register_signals();

	mmt_sec_init( excludes_rules_mask );

	//the last thread is used as main thread
	if( threads_count > 0 )
		threads_count --;

	sec_handler =  mmt_sec_register( threads_count, core_mask, rule_mask, verbose, _print_output, NULL );

	mmt_sec_set_ignore_remain_flow(sec_handler, can_ignore_remain_flow, 100000);

	if( core_mask != NULL ){
		//main thread on the last core
		if( move_the_current_thread_to_a_processor( core_mask[ threads_count ], -15 ) )
			mmt_warn("Cannot set affinity of process %d on lcore %d", gettid(), core_mask[ threads_count ] );

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


	_update_and_register_protocols_attributes_to_extract( true );


	//Register a packet handler, it will be called for every processed packet
	register_packet_handler(mmt_dpi_handler, 1, packet_handler, sec_handler );

	_print_add_rm_rules_instruction();

	if (type == TRACE_FILE) {
		mmt_info("Analyzing pcap file %s", filename );
		pcap = pcap_open_offline(filename, errbuf); // open offline trace
		if (!pcap) { /* pcap error ? */
			mmt_halt("pcap_open failed for the following reason: %s\n", errbuf);
		}

		while ((data = pcap_next(pcap, &p_pkthdr)) ) {
			//allow user to add/rm rules
			_add_or_remove_rules_if_need();

			header.ts     = p_pkthdr.ts;
			header.caplen = p_pkthdr.caplen;
			header.len    = p_pkthdr.len;
			if (!packet_process(mmt_dpi_handler, &header, data))
				mmt_sec_log(ERROR, "Packet data extraction failure.\n");
		}

	} else {
		mmt_info("Listening on interface %s", filename );

		pcap = pcap_create( filename, errbuf);
		if (pcap == NULL)
			mmt_halt("Couldn't open device %s\n", errbuf);

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

