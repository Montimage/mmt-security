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
#include <inttypes.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "dpi/types_defs.h"
#include "dpi/mmt_dpi.h"
#include "lib/mmt_lib.h"
#include "lib/mmt_smp_security.h"
#include "lib/mmt_sec_config.h"
#include "lib/system_info.h"

//maximum length of a report sent from mmt-probe
#define REPORT_SIZE 10000
//maximum length of file name storing alerts
#define MAX_FILENAME_SIZE 500

#define STRING 1
#define VOID   2

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

typedef struct _sec_handler_struct{
	void *handler;

	void (*process_fn)( const void *, message_t *);

	int threads_count;
}_sec_handler_t;

//print out detailed message
static bool verbose                     = NO;
static _sec_handler_t _sec_handler;
static const rule_info_t **rules_arr    = NULL;
static size_t proto_atts_count          = 0;
static message_element_t *proto_atts    = NULL;
//id of socket
static int socket_server                = 0;

static pid_t parent_pid = 0;

static char output_file_string[MAX_FILENAME_SIZE + 1]  = {0};
static char output_redis_string[MAX_FILENAME_SIZE + 1] = {0};


static inline double time_diff(struct timeval t1, struct timeval t2) {
	return (double)(t2.tv_sec - t1.tv_sec) + (t2.tv_usec - t1.tv_usec)/1000000.0;
}

void usage(const char * prg_name) {
	fprintf(stderr, "%s [<option>]\n", prg_name);
	fprintf(stderr, "Option:\n");
	fprintf(stderr, "\t-p <number/string> : If p is a number, it indicates port number of internet domain socket otherwise it indicates name of unix domain socket. Default: 5000\n");
	fprintf(stderr, "\t-n <number> : Number of threads per process. Default = 1\n");
	fprintf(stderr, "\t-c <string> : Gives the range of logical cores to run on, e.g., \"1,3-8,16\"\n");
	fprintf(stderr, "\t-f <string> : Output results to file, e.g., \"/home/tata/:5\" => output to folder /home/tata and each file contains reports during 5 seconds \n");
	fprintf(stderr, "\t-r <string> : Output results to redis, e.g., \"localhost:6379\"\n");
	fprintf(stderr, "\t-v          : Verbose.\n");
	fprintf(stderr, "\t-l          : Prints the available rules then exit.\n");
	fprintf(stderr, "\t-h          : Prints this help.\n");
	exit(1);
}

size_t parse_options(int argc, char ** argv, uint16_t *rules_id, int *port_no, char *unix_domain, size_t *threads_count,
		size_t *cores_count, uint8_t **core_mask, bool *verbose ) {
	int opt, optcount = 0, x;

	while ((opt = getopt(argc, argv, "p:n:f:r:c:vlh")) != EOF) {
		switch (opt) {
		case 'p':
			optcount++;

			x = atoi( optarg );
			*port_no = x;
			if( x == 0 ){
				strncpy((char *) unix_domain, optarg, MAX_FILENAME_SIZE);
			}
			break;
		case 'f':
			optcount++;
			strncpy((char *) output_file_string, optarg, MAX_FILENAME_SIZE);
			break;
		case 'r':
			optcount++;
			strncpy((char *) output_redis_string, optarg, MAX_FILENAME_SIZE);
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
		case 'c':
			optcount++;
			*cores_count = expand_number_range( optarg, core_mask );
			if( *cores_count == 0 )
				usage(argv[0]);
			break;
		case 'l':
			mmt_sec_print_rules_info();
			exit( 0 );
		case 'v':
			optcount++;
			*verbose = YES;
			break;
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

#ifdef DEBUG_MODE
	mmt_warn( "Unknown data type of attribute %"PRIu32" of protocol %"PRIu32, att_id, proto_id );
#endif

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
	size_t elements_count;

	while( 1 ){
		//Read 4 bytes first to know the length of the report
		n = recv( sock, &length_of_report, 4, MSG_WAITALL );

		//end of socket flow
		if ( unlikely( n == 0 ))	break;

		if( unlikely( length_of_report > REPORT_SIZE )){
			mmt_warn("Overflow: length_of_report = %d", length_of_report );
			length_of_report = REPORT_SIZE;
		}
		else if( unlikely( length_of_report < 0 )){
			mmt_info( "Impossible len = %d", length_of_report );
			continue;
		}

		n = recv( sock, buffer, length_of_report-4, MSG_WAITALL );

		if( unlikely( n == 0 ))
			mmt_halt( "Error: Cannot read data of report having size = %d", length_of_report );

		index = 0;

		//parser data
		//number of elements
		elements_count = (uint8_t) buffer[ index ];
		index += 1;

		msg = create_message_t( elements_count );

		msg->timestamp = mmt_sec_encode_timeval( ( struct timeval * ) &( buffer[index] ) );
		index += sizeof (struct timeval);//16

		msg->counter = reports_count; //TODO

		for(counter = 0; counter < msg->elements_count; counter ++){
			el_ptr = &msg->elements[ counter ];
			//protocol ID
			el_ptr->proto_id = *(uint32_t *) &buffer[index];
			index += 4;

			//attribute ID
			el_ptr->att_id = *(uint32_t*) &buffer[index];
			index += 4;

			//data length
			el_data_length = *(uint16_t *) &buffer[index];
			index += 2;

			//data
			el_data_type = _get_data_type( el_ptr->proto_id, el_ptr->att_id );

			//special processing for these data types
			if( likely( el_data_type == MMT_HEADER_LINE || el_data_type == MMT_DATA_POINTER )){
				el_ptr->data      = mmt_mem_dup( &buffer[index], el_data_length );
				el_ptr->data_type = STRING;
			}
			else if( likely( el_data_type != -1 ))
				mmt_sec_convert_data( &buffer[index], el_data_type, &el_ptr->data, &el_ptr->data_type );
			else{
				el_ptr->data      = NULL;
				el_ptr->data_type = VOID;
			}

			index += el_data_length;

			if( unlikely( index >= length_of_report )){
				mmt_halt( "Data format received from mmt-probe is not correct." );
				break;
			}
		}

		//call mmt_security
		_sec_handler.process_fn( _sec_handler.handler, msg );

		reports_count ++;
	}

	return reports_count;
}

static inline size_t termination(){
	size_t alerts_count = 0;

	if( _sec_handler.threads_count > 1 )
		alerts_count = mmt_smp_sec_unregister( _sec_handler.handler, NO );
	else
		alerts_count = mmt_sec_unregister( _sec_handler.handler );

	mmt_mem_free( proto_atts );
	mmt_mem_free( rules_arr );

	return alerts_count;
}


void signal_handler_seg(int signal_type) {
	mmt_error( "Interrupted by signal %d", signal_type );

	close( socket_server );
	mmt_print_execution_trace();
	usleep( 50 );
	exit( signal_type );
}

void signal_handler(int signal_type) {
	static volatile int times_counter = 0;
	size_t alerts_count;
	pid_t pid = getpid();
	int status;

	close( socket_server );

	if( times_counter >= 1 ) exit( signal_type );
	times_counter ++;

	if( pid == parent_pid )
		mmt_error( "Interrupted proc %d by signal %d", pid, signal_type );

	if( signal_type == SIGINT ){
		if( pid == parent_pid )
			mmt_error("Releasing resource ... (press Ctrl+c again to exit immediately)");

		signal(SIGINT, signal_handler);
	}
	sleep( 1 );//waiting for everything finish
	alerts_count = termination();

	//print only for child process
	if( verbose && parent_pid != pid )
		mmt_info("Process %d generated %zu alerts", pid, alerts_count );

	//parent waits for all children
	if( parent_pid == pid ) wait( &status );

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


int main( int argc, char** argv ) {
	uint32_t port_number = 5000; //port on that the program listens
	size_t threads_count = 1;    //number of threads for each process

	uint16_t *rules_id_filter;
	const proto_attribute_t **p_atts;
	int client_socket, pid, i;

	char str_buffer[256];
	const size_t str_buffer_size = 256;

	struct sockaddr_in in_server_addr, in_cli_addr;
	struct sockaddr_un un_server_addr, un_cli_addr;

	char un_domain_name[ MAX_FILENAME_SIZE + 1 ];
	bool is_unix_socket = NO;

	socklen_t socklen;
	struct timeval start_time, end_time;
	size_t size, rules_count, cores_count = 0, clients_count = 0, alerts_count = 0;
	uint8_t *core_mask = NULL, *core_mask_ptr;

	mmt_sec_callback _print_output;

	parent_pid = getpid();

	parse_options(argc, argv, rules_id_filter, &port_number, un_domain_name, &threads_count, &cores_count, &core_mask, &verbose );

	is_unix_socket = (port_number == 0);

	mmt_assert( threads_count == 1 || threads_count <= cores_count, "Core mask is not enough for %zu threads",  threads_count );

	mmt_assert( threads_count > 0 && cores_count % threads_count == 0, "Number of lcores must be multiple of %zu", threads_count );

	//get all available rules
	rules_count = mmt_sec_get_rules_info( &rules_arr );

	//init mmt-sec to verify the rules
	_sec_handler.threads_count = threads_count;

	/* create internet socket */
	if( is_unix_socket == NO ){
		socket_server = socket( AF_INET, SOCK_STREAM, 0 );

		if( socket_server < 0) mmt_halt("Error on opening socket");


		/* Initialize socket structure */
		bzero((char *) &in_server_addr, sizeof( in_server_addr ));

		in_server_addr.sin_family      = AF_INET;
		in_server_addr.sin_addr.s_addr = htonl( INADDR_ANY );
		in_server_addr.sin_port        = htons( port_number );

		/* Now bind the host address using bind() call.*/
		mmt_assert( bind(socket_server, (struct sockaddr *) &in_server_addr, sizeof(in_server_addr)) >= 0,
			"Error on binding");
		socklen = sizeof( in_cli_addr );
	}else{
		//create unix socket
		socket_server = socket( AF_UNIX, SOCK_STREAM, 0 );

		if( socket_server < 0) mmt_halt("Error on opening socket");


		/* Initialize socket structure */
		bzero((char *) &un_server_addr, sizeof( un_server_addr ));

		un_server_addr.sun_family = AF_UNIX;
		strcpy( un_server_addr.sun_path, un_domain_name );
		unlink( un_server_addr.sun_path );

		/* Now bind the host address using bind() call.*/
		mmt_assert( bind( socket_server, (struct sockaddr *) &un_server_addr, sizeof( un_server_addr) ) >= 0,
				"Error on binding");
		socklen = sizeof( un_cli_addr );
	}

	/* Now start listening for the clients, here
	 * process will go in sleep mode and will wait
	 * for the incoming connection
	 */
	listen( socket_server, 5 );//limit the number of outstanding connections in the socket's listen queue


	if( verbose ){
		if( is_unix_socket == NO )
			mmt_info(" MMT-Security version %s verifies %zu rule(s) using %zu thread(s).\n\tIt is listening on port %d\n",
					mmt_sec_get_version_info(), rules_count, threads_count, port_number );
		else
			mmt_info(" MMT-Security version %s verifies %zu rule(s) using %zu thread(s).\n\tIt is listening on \"%s\"\n",
					mmt_sec_get_version_info(), rules_count, threads_count, un_domain_name );
	}
	clients_count = 0;
	core_mask_ptr = NULL;

	register_signals();
	//ignore child fate, don't let it become zombie
	signal( SIGCHLD, SIG_IGN );

	//this loop will be broken by Ctrl+c
	while( 1 ) {
			//accept: wait for a connection request
		if( is_unix_socket == NO )
			client_socket = accept( socket_server, (struct sockaddr *) &in_cli_addr, &socklen );
		else //unix socket
			client_socket = accept( socket_server, (struct sockaddr *) &un_cli_addr, &socklen );

		if( client_socket < 0 ) mmt_halt("Error on accept");

		if( core_mask )
			core_mask_ptr = &core_mask[ clients_count * threads_count % cores_count ];

		clients_count ++;

		/* Create child process */
		pid = fork();

		if( pid < 0 ){
			mmt_error("Cannot fork a new process");
			close( client_socket );
			continue;
		}
		else if (pid == 0) {
			/*===========================*/
			/* This is the child process */

			// child doesn't need the listener
			close( socket_server );

			if( verbose ){
				//convert client's IP to readable text
				if( is_unix_socket == NO ){
					inet_ntop(AF_INET, &in_cli_addr.sin_addr.s_addr, str_buffer, str_buffer_size );
					mmt_info( "%3zuth connection is coming from %s:%d ... processed by proc. %d",
							clients_count, str_buffer, in_cli_addr.sin_port, getpid() );
				}else{
					mmt_info( "%3zuth connection is coming from local ... processed by proc. %d",
							clients_count, getpid() );
				}
			}

			if( core_mask_ptr != NULL ){
				//main thread on the last core
				if( move_the_current_thread_to_a_processor( core_mask_ptr[ threads_count - 1 ], -15 ) )
					mmt_warn("Cannot set affinity of process %d on lcore %d", gettid(), core_mask_ptr[ threads_count - 1 ] );
			}

			//register signal handler for this child process
			register_signals();

			//do not need output
			if( output_file_string[0] == '\0' &&  output_redis_string[0] == '\0' )
				_print_output = NULL;
			else
				_print_output = mmt_sec_print_verdict;

			//init mmt-sec to verify the rules
			if( _sec_handler.threads_count == 1 ){
				_sec_handler.handler    = mmt_sec_register( rules_arr, rules_count, _print_output, NULL );
				_sec_handler.process_fn = &mmt_sec_process;
				size = mmt_sec_get_unique_protocol_attributes( _sec_handler.handler, &p_atts );
			}else if( _sec_handler.threads_count > 1 ){
				_sec_handler.handler    = mmt_smp_sec_register( rules_arr, rules_count, threads_count - 1, core_mask_ptr, verbose && clients_count == 1, _print_output, NULL );
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
				mmt_debug("p_atts[i]->proto_id = %u, p_atts[i]->att_id = %u, proto_atts[i].data_type = %d", p_atts[i]->proto_id, p_atts[i]->att_id, proto_atts[i].data_type);
			}

			//init output
			verdict_printer_init( output_file_string, output_redis_string );

			//mark the starting moment
			if( verbose )
				gettimeofday( &start_time, NULL );

			//do processing
			size = receiving_reports( client_socket );

			close( client_socket );

			//finish
			alerts_count = termination();

			if( verbose ){
				gettimeofday( &end_time, NULL );
				mmt_info( "%3zuth connection sent %9zu reports, in %7.2fs, generated %9zu alerts",
						clients_count, size, time_diff( start_time, end_time ), alerts_count
				);
			}

			mmt_mem_free( core_mask );

			verdict_printer_free();

			exit( EXIT_SUCCESS );

			/*End of child process       */
			/*===========================*/
		}
		else {
			/* pid > 0. This is the parent process.
			 * The child process handles the connection,
			 * so we don't need our copy of the connected socket descriptor.
			 * Close it.  Then continue with the loop and accept another connection.
			 */
			close( client_socket );
		}
	}

	termination();

	return EXIT_SUCCESS;
}
