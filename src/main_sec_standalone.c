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

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <unistd.h>
#include "mmt_core.h"
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "lib/mmt_lib.h"
#include "lib/plugin_header.h"
#include "lib/mmt_security.h"

#define MAX_FILENAME_SIZE 256
#define TRACE_FILE 1
#define LIVE_INTERFACE 2
#define MTU_BIG (16 * 1024)

void print_rules_info(){
	const rule_info_t **rules_arr;
	size_t i, j, n;

	n = load_plugins( &rules_arr );

	printf("Found %zu rule%s", n, n<=1? ".": "s." );

	for( i=0; i<n; i++ ){
		printf("\n%zu - Rule id: %d", (i+1), rules_arr[i]->id );
		printf("\n\t- type            : %s",  rules_arr[i]->type_string );
		printf("\n\t- events_count    : %d",  rules_arr[i]->events_count );
		printf("\n\t- variables_count : %zu",  rules_arr[i]->proto_atts_count );
		printf("\n\t- variables       : " );
		for( j=0; j<rules_arr[i]->proto_atts_count; j++ )
			printf( "%s%s.%s",
					j==0? "":", ",
							rules_arr[i]->proto_atts[j].proto, rules_arr[i]->proto_atts[j].att);

		printf("\n\t- description     : %s",  rules_arr[i]->description );
		printf("\n\t- if_satisfied    : %s",  rules_arr[i]->if_satisfied );
		printf("\n\t- if_not_satisfied: %s",  rules_arr[i]->if_not_satisfied );
		printf("\n\t- create_instance : %p",  rules_arr[i]->create_instance );
		printf("\n\t- convert_message : %p",  rules_arr[i]->convert_message );
		printf("\n\t- hash_message    : %p",  rules_arr[i]->hash_message );
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
	fprintf(stderr, "\t-r <rule_list> : Gives the list of rules'id, separated by comma, for analysis. Default: analyze all available rules.\n");
	fprintf(stderr, "\t-l             : Prints the available rules then exit.\n");
	fprintf(stderr, "\t-h             : Prints this help.\n");
	exit(1);
}

size_t parse_options(int argc, char ** argv, char * filename, int * type, uint16_t *rules_id) {
	int opt, optcount = 0;
	while ((opt = getopt(argc, argv, "t:i:qh")) != EOF) {
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
		case 'r':
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

void packet_handler(const ipacket_t * ipacket, void * args) {
	//debug("packet_handler of %"PRIu64" index: %d\n",ipacket->packet_id,ipacket->extra.index);

}

void live_capture_callback( u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data )
{
	mmt_handler_t *mmt = (mmt_handler_t*)user;
	struct pkthdr header;
	header.ts = p_pkthdr->ts;
	header.caplen = p_pkthdr->caplen;
	header.len = p_pkthdr->len;
	if (!packet_process( mmt, &header, data )) {
		fprintf(stderr, "Packet data extraction failure.\n");
	}
}

int main(int argc, char** argv) {
	mmt_handler_t *mmt_handler;
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
	mmt_sec_handler_t *mmt_sec_handler;
	uint16_t *rules_id_filter;

	size = load_plugins( &rules_arr );

	parse_options(argc, argv, filename, &type, rules_id_filter );

	//init mmt_dpi extraction
	init_extraction();

	//Initialize dpi handler
	mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
	if (!mmt_handler) { /* pcap error ? */
		fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
		return EXIT_FAILURE;
	}

	//Register a packet handler, it will be called for every processed packet
	for( i=0; i<size; i++ ){
		for( j=0; j<rules_arr[i]->proto_atts_count; j++ )
			register_extraction_attribute_by_name( mmt_handler,
					rules_arr[i]->proto_atts[j].proto,
					rules_arr[i]->proto_atts[j].att );
	}

	mmt_sec_handler = mmt_sec_register( rules_arr, size, print_verdict, NULL );

	//Register a packet handler to periodically report protocol statistics
	register_packet_handler(mmt_handler, 1, packet_handler, (void *)mmt_sec_handler );



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
			if (!packet_process(mmt_handler, &header, data)) {
				fprintf(stderr, "Packet data extraction failure.\n");
			}
		}
	} else {
		pcap = pcap_open_live(filename, MTU_BIG, 1, 1000, errbuf);
		if (!pcap) {
			fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
			return EXIT_FAILURE;
		}
		(void)pcap_loop( pcap, -1, &live_capture_callback, (u_char*)mmt_handler );
	}

	mmt_close_handler(mmt_handler);

	close_extraction();

	pcap_close(pcap);

	mmt_sec_unregister( mmt_sec_handler );
	mmt_free( rules_arr );

	return EXIT_SUCCESS;
}

