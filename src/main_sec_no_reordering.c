/*
 * main_sec_no_reordering.c
 * Lock and unlock rhythmically between receiving threads and processing threads (one report coming, one report going).
 *  Created on: Nov 29, 2016
 *      Author: vinh
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>

#include "dpi/mmt_dpi.h"
#include "lib/mmt_lib.h"
#include "lib/mmt_smp_security.h"
#include "lib/mmt_sec_config.h"
#include "lib/system_info.h"

//maximum length of a report sent from mmt-probe
#define REPORT_SIZE 256

#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif

typedef struct _sec_handler_struct{
	void *handler;

	void (*process_fn)( const void *, const message_t *);

	int threads_count;
}_sec_handler_t;


static _sec_handler_t _sec_handler;
static const rule_info_t **rules_arr = NULL;
static size_t proto_atts_count       = 0;
static message_element_t *proto_atts = NULL;
//id of socket
static int socket_fd                 = 0;
static volatile bool is_stop_processing = NO;

static inline double time_diff(struct timeval t1, struct timeval t2) {
	return (double)(t2.tv_sec - t1.tv_sec) + (t2.tv_usec - t1.tv_usec)/1000000.0;
}

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
	mmt_mem_free( rules_arr );
}


void usage(const char * prg_name) {
	fprintf(stderr, "%s [<option>]\n", prg_name);
	fprintf(stderr, "Option:\n");
	fprintf(stderr, "\t-p <number>: Port number. Default = 5000\n");
	fprintf(stderr, "\t-n <number>: Number of threads. Default = 1\n");
	fprintf(stderr, "\t-l         : Prints the available rules then exit.\n");
	fprintf(stderr, "\t-h         : Prints this help.\n");
	exit(1);
}

size_t parse_options(int argc, char ** argv, uint16_t *rules_id, int *port_no, size_t *threads_count ) {
	int opt, optcount = 0, x;
	char * config_file;

	while ((opt = getopt(argc, argv, "p:n:lh")) != EOF) {
		switch (opt) {
		case 'p':
			optcount++;
			if (optcount < 1) {
				usage(argv[0]);
			}
			x = atoi( optarg );
			if( x >= 0 )
				*port_no = x;
			else
				usage(argv[0]);
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
		default: usage(argv[0]);
		}
	}

	return 0;
}


static inline int _get_data_type( uint32_t proto_id, uint32_t att_id ){
	size_t i;
	for( i=0; i<proto_atts_count; i++ )
		if( proto_atts[ i ].proto_id == proto_id && proto_atts[ i ].att_id == att_id ){
			return proto_atts[ i ].data_type;
		}

	mmt_warn( "Unknown data type of attribute %"PRIu32" of protocol %"PRIu32, proto_id, att_id );
	return -1;
}

/**
 * Received reports from mmt-probe.
 * For each incoming report, the function will converts them to a #message_t type,
 *  then passes it to #mmt_security
 */
static inline size_t receiving_reports( int sock ) {
	size_t reports_count = 0;
	size_t index = 0, n;
	uint8_t buffer[ REPORT_SIZE ], *buf_ptr; //utf-8

	uint32_t length_of_report = 0;
	message_t *msg;
	message_element_t *el_ptr;
	uint16_t el_data_length;
	int el_data_type;
	size_t counter;
	struct timeval start_time, end_time;

	//mark the starting moment
	gettimeofday(&start_time, NULL);

	while( !is_stop_processing ){
		n = recv( sock, &length_of_report, 4, MSG_WAITALL );//Read 4 bytes first to know the length of the report
		//end of socket flow
		if ( n == 0 )	break;

		if( unlikely( length_of_report > REPORT_SIZE )){
			mmt_warn("Overflow: length_of_report = %d", length_of_report );
			length_of_report = REPORT_SIZE;
		}
		else if( length_of_report < 0 )
			mmt_info( "Impossible len = %d", length_of_report );

		n = recv( sock, buffer, length_of_report-4, MSG_WAITALL );

		if( unlikely( n == 0 ))
			mmt_halt( "Error: Cannot read data of report having size = %d", length_of_report );

		index = 0;

		//parser data
		msg = mmt_mem_alloc( sizeof( message_t ));

		//number of elements
		msg->elements_count = (uint8_t) buffer[ index ];
		index += 1;

		//allocate memory to store the elements
		msg->elements = mmt_mem_alloc( sizeof( message_element_t) * msg->elements_count );
		bzero( msg->elements, sizeof( message_element_t) * msg->elements_count );

		msg->timestamp = mmt_sec_encode_timeval( ( struct timeval * ) &( buffer[index] ) );
		index += sizeof (struct timeval);//16

		msg->counter = reports_count; //TODO

		for(counter = 0; counter < msg->elements_count; counter ++){
			el_ptr = &msg->elements[ counter ];
			//protocol ID
			memcpy( &el_ptr->proto_id, &buffer[index], 4 );
			index += 4;

			//attribute ID
			memcpy( &el_ptr->att_id, &buffer[index], 4 );
			index += 4;

			//data length
			memcpy( &el_data_length, &buffer[index], 2 );
			index += 2;

			//data
			el_data_type = _get_data_type( el_ptr->proto_id, el_ptr->att_id );
			if( el_data_type != -1 )
				mmt_sec_convert_data( &buffer[index], el_data_type, &el_ptr->data, &el_ptr->data_type );
			else
				el_ptr->data = NULL;

			index += el_data_length;

			if( unlikely( index >= length_of_report )){
				mmt_warn( "Data format is not correct." );
				break;
			}
		}

		//call mmt_security
		_sec_handler.process_fn( _sec_handler.handler, msg );

		//free msg after using
		free_message_t( msg );

		reports_count ++;
	}

	gettimeofday( &end_time, NULL );
	fprintf( stderr, "  received %zu reports, processed in  %.2fs\n",
			reports_count, time_diff( start_time, end_time ));

	close( sock );
	return reports_count;
}

static inline void termination(){

	close( socket_fd );
	mmt_mem_free( proto_atts );

	if( _sec_handler.threads_count > 1 )
		mmt_smp_sec_unregister( _sec_handler.handler, NO );
	else
		mmt_sec_unregister( _sec_handler.handler );

	mmt_mem_free( rules_arr );
	mmt_mem_print_info();
}


void signal_handler_seg(int signal_type) {
	is_stop_processing = YES;
	mmt_print_execution_trace();
	usleep( 50 );
	exit( signal_type );
}

void signal_handler(int signal_type) {
	static volatile int times_counter = 0;
	is_stop_processing = YES;
	if( times_counter >= 1 ) exit( signal_type );
	times_counter ++;

	mmt_error( "Interrupted by signal %d", signal_type );

	if( signal_type == SIGINT ){
		mmt_error("Releasing resource ... (press Ctrl+c again to exit immediately)");
		signal(SIGINT, signal_handler);
	}
	sleep( 2 );//waiting for everything finish
	termination();
	exit( signal_type );
}


void register_signals(){
	signal(SIGSEGV, signal_handler_seg );
	signal(SIGINT,  signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGABRT, signal_handler);
}


int main( int argc, char** argv ) {
	uint32_t portno   = 5000;
	size_t nb_thr_sec = 1;

	uint16_t *rules_id_filter;
	const proto_attribute_t **p_atts;
	int childfd, pid, i;

	char str_buffer[256];
	const size_t str_buffer_size = 256;

	struct sockaddr_in serv_addr, cli_addr;
	socklen_t socklen;

	size_t size, rules_count;

	parse_options(argc, argv, rules_id_filter, &portno, &nb_thr_sec );

	register_signals();

	//get all available rules
	rules_count = mmt_sec_get_rules_info( &rules_arr );

	//init mmt-sec to verify the rules
	_sec_handler.threads_count = nb_thr_sec;

	//init mmt-sec to verify the rules
	if( _sec_handler.threads_count == 1 ){
		_sec_handler.handler    = mmt_sec_register( rules_arr, rules_count, mmt_sec_print_verdict, NULL );
		_sec_handler.process_fn = &mmt_sec_process;
		size = mmt_sec_get_unique_protocol_attributes( _sec_handler.handler, &p_atts );
	}else{
		_sec_handler.handler    = mmt_smp_sec_register( rules_arr, rules_count, nb_thr_sec, mmt_sec_print_verdict, NULL );
		_sec_handler.process_fn = &mmt_smp_sec_process;
		size = mmt_smp_sec_get_unique_protocol_attributes( _sec_handler.handler, &p_atts );
	}

	//Remember proto_id/att_id to get data_type for each report element receveived from mmt-probe
	proto_atts_count = size;
	proto_atts = mmt_mem_alloc( size * sizeof( message_element_t ));
	for( i=0; i<size; i++ ){
		proto_atts[i].proto_id  = p_atts[i]->proto_id;
		proto_atts[i].att_id    = p_atts[i]->att_id;
		proto_atts[i].data_type = get_attribute_data_type( p_atts[i]->proto_id, p_atts[i]->att_id );
		//mmt_debug("p_atts[i]->proto_id = %u, p_atts[i]->att_id = %u, proto_atts[i].data_type = %d", p_atts[i]->proto_id, p_atts[i]->att_id, proto_atts[i].data_type);
	}

	/* First call to socket() function */
	socket_fd = socket( AF_INET, SOCK_STREAM, 0 );

	if( socket_fd < 0) mmt_halt("ERROR opening socket");

	/* Initialize socket structure */
	bzero((char *) &serv_addr, sizeof( serv_addr ));

	serv_addr.sin_family      = AF_INET;
	serv_addr.sin_addr.s_addr = htonl( INADDR_ANY );
	serv_addr.sin_port        = htons( portno );

	/* Now bind the host address using bind() call.*/
	if( bind(socket_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0 ) mmt_halt("Error on binding");

	/* Now start listening for the clients, here
	 * process will go in sleep mode and will wait
	 * for the incoming connection
	 */
	listen( socket_fd, 5 );//int listen(int socket, int backlog);  limit the number of outstanding connections in the socket's listen queue

	socklen = sizeof( cli_addr );

	mmt_info(" MMT-Security version %s verifies %zu rule(s) using %zu thread(s).\n\tIt is listening on port %d\n",
			mmt_sec_get_version_info(), rules_count, nb_thr_sec, portno );

	//this loop will be broken by Ctrl+c
	while( !is_stop_processing ) {
			//accept: wait for a connection request
			childfd = accept( socket_fd, (struct sockaddr *) &cli_addr, &socklen );

			if (childfd < 0) mmt_halt("Error on accept");

			//convert client's IP to readable text
			inet_ntop(AF_INET, &cli_addr.sin_addr.s_addr, str_buffer, str_buffer_size );
			mmt_info("A new connection is coming from %s:%d ...", str_buffer, cli_addr.sin_port );

			/* Create child process */
			pid = fork();
			if (pid < 0) error("ERROR on fork");

			if (pid == 0) {
				/* This is the child process */
				close(socket_fd);
				//do processing
				receiving_reports( childfd );
				//finish
				termination();
				exit( EXIT_SUCCESS );
			}
			else {
				/* pid > 0. This is the parent process.
				 * The child process handles the connection,
				 * so we don't need our copy of the connected socket descriptor.
				 * Close it.  Then continue with the loop and accept another connection.
				 */
				close( childfd );
			}

	}

	termination();

	return EXIT_SUCCESS;
}
