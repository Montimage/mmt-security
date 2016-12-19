/*
 * main_sec_server.c
 *
 *  Created on: Nov 3, 2016
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
#include <pthread.h>
#include <sys/time.h>
#include "lib/mmt_log.h"
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include<sys/ipc.h>
#include<sys/shm.h>
#include <sys/socket.h>
#include "dpi/types_defs.h"
#include "lib/expression.h"
#include "lib/mmt_lib.h"
#include "lib/plugin_header.h"
#include "lib/mmt_smp_security.h"
#include "dpi/mmt_dpi.h"
#include "dpi/types_defs.h"
#include "lib/mmt_sec_config.h"
#include "lib/system_info.h"

#define REPORT_SIZE 2000
#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif

struct timeval start_t, end_t;

static mmt_smp_sec_handler_t *mmt_smp_sec_handler = NULL;
static const rule_info_t **rules_arr = NULL;
static size_t proto_atts_count = 0;
static message_element_t *proto_atts = NULL;
static int connectcnt=0;
//static int nbr_thr_p = 1; //nbr of mmt_sec processing threads
static bool recev_s[10]; //identifying the state of each connection (unfinished?)
static bool notdone = YES; //use notdone to terminate the server
static bool receiv_s_glob = YES;
static mmt_sec_config_struct_t *mmt_sec_config_struct;
static bool condition_v[10];

typedef struct report_element{
	uint32_t proto_id;
	uint32_t att_id;
	uint16_t data_len;
	void *data;
} report_element_t;

typedef struct report {
	int flag; //TODO (to know if we can delete node or not)
	int counter; //TODO (it can be report_ID and acts like the sequence)
	size_t elements_count;
	struct timeval timestamp;
	report_element_t *report_elements;
	struct report * next;
	struct report * prev;
} report_t;
static struct report *report_list = NULL;
//static struct report *head_queue = NULL;
struct thr_r_arg_struct{
	int sock;
	int index;
	uint16_t threshold_size;
	uint16_t threshold_time;
};

struct thr_p_arg_struct{
	mmt_smp_sec_handler_t *mmt_smp_sec_handl;
	int index;
};

struct {
	pthread_spinlock_t spinlock_cr; //lock to count the reports received
	pthread_spinlock_t spinlock_processing; //lock for processing threads
	pthread_mutex_t mutex_str; //lock to insert the reports
	pthread_mutex_t mutex_recv_s; //lock for determining receiving state = YES/NO
	int count_str; //count the reports stored
	int count_rcv; //count the reports received
} thread_lock;

pthread_cond_t cond[10];
pthread_mutex_t mutex;
pthread_t thr_p_rest;

void error(const char *msg)
{
	perror(msg);
	exit(1);
}

int time_diff(struct timeval t1, struct timeval t2) {
	return (((t2.tv_sec - t1.tv_sec) * 1000000) + (t2.tv_usec - t1.tv_usec));
}

int timevalcmp (struct timeval tv1, struct timeval tv2){
	if ((int) tv1.tv_sec > (int) tv2.tv_sec) return 1;
	if (((int) tv1.tv_sec == (int) tv2.tv_sec) && ((int) tv1.tv_usec > (int) tv2.tv_usec)) return 1;
	return 0;
}

int free_report_t(report_t *node){
	int i;
	if (node==NULL) return 1; //nothing to do
	for (i=0; i<node->elements_count; i++){
		mmt_mem_free(node->report_elements[i].data);
	}
	mmt_mem_free(node->report_elements);
	mmt_mem_free(node);
	return 0;
}

/*Pop/Delete last node (FIFO-Queue)*/
int pop_last(report_t **head)
{	int i;
report_t * last;
/*Only one node*/
if (thread_lock.count_str==0) return 1;
if (thread_lock.count_str==1) { //one node
	//free_report_t(*head);
	*head = NULL;
	return 0;
}
if(thread_lock.count_str==2){ //2 nodes
	last = (*head)->next;
	(*head)->next = NULL;
	(*head)->prev = *head;
	//free_report_t(last);
	return 0;
}
//more than 2 nodes
last = (*head)->prev;
last->prev->next = NULL;
(*head)->prev = last->prev;
//free_report_t(last);
return 0;
}

/*Insert a new node to the double linked list that was
 * in good order of data*/

int insert(report_t **head, report_t *report_node)
{
	report_t * current, * temp;

	// The list is empty
	if (thread_lock.count_str==0) {
		//mmt_debug("Add the first node\n");
		*head = report_node;
		(*head)->prev = report_node;//if the node has only one node, head->prev = head; head->next = NULL
		(*head)->next = NULL;
		return 0;
	}

	// The list contains only one node
	if (thread_lock.count_str==1){
		if (timevalcmp((*head)->timestamp, report_node->timestamp)==0) { //add to the beginning
			//mmt_debug("One node. Add to the beginning\n");
			temp = report_node;
			(*head)->prev = temp;
			temp->next = *head;
			temp->prev = *head;
			*head = temp;
			return 0;
		}
		else { //add to the end
			//mmt_debug("One node. Add to the end\n");
			report_node->prev = *head;
			(*head)->next = report_node;
			(*head)->prev = report_node;
			return 0;
		}
	}

	// The list contains at least two nodes
	current = *head;
	while((timevalcmp(current->timestamp,report_node->timestamp))&&(current->next!=NULL))
	{
		current = current -> next;
	}
	if (current==*head){ //timestamp is bigger than the first node, add to the beginning
		//mmt_debug("At least two nodes. Add to the beginning\n");
		temp = report_node;
		temp->next = *head;
		temp->prev = (*head)->prev;
		(*head)->prev = temp;
		*head = temp;
		return 0;
	}
	if (current->next==NULL){
		if (timevalcmp(current->timestamp, report_node->timestamp)==1) {//add to the end
			//mmt_debug("At least two nodes. Add to the end\n");
			current->next = report_node;
			report_node->prev = current;
			(*head)->prev = report_node;
			return 0;
		}
	}
	//there exist prev_node and after_node (current) to add new node between them
	//mmt_debug("At least two nodes. Add to the middle\n");
	temp = report_node;
	current->prev->next = temp;
	temp->prev = current->prev;
	temp->next = current;
	current->prev = temp;
	return 0;
}


/* Print the timestamp of nodes in list */
void print_list(report_t *head)
{
	report_t * current = head;
	while(current != NULL)
	{
		printf("Timestamp: %lu.%lu",current->timestamp.tv_sec, current->timestamp.tv_usec);
		current = current->next;
		printf("\n");
	}
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

void print_verdict( const rule_info_t *rule,		//id of rule
		enum verdict_type verdict,
		uint64_t timestamp,  //moment the rule is validated
		uint32_t counter,
		const mmt_array_t *const trace,
		void *user_data ){

	struct timeval now;
	gettimeofday(&now, NULL);

	char *string = convert_execution_trace_to_json_string( trace, rule );

	printf( "{\"timestamp\":%ld.%ld,\"pid\":%"PRIu32",\"verdict\":\"%s\",\"type\":\"%s\",\"cause\":\"%s\",\"history\":%s},\n",
			now.tv_sec, now.tv_usec,
			rule->id, verdict_type_string[verdict],  rule->type_string,  rule->description, string );

	mmt_mem_free( string );
}

void usage(const char * prg_name) {
	fprintf(stderr, "%s [<option>]\n", prg_name);
	fprintf(stderr, "Option:\n");
	fprintf(stderr, "\t-c <config file>: Start MMT-SEC server\n");
	fprintf(stderr, "\t-l: Prints the available rules then exit.\n");
	fprintf(stderr, "\t-h: Prints this help.\n");
	exit(1);
}

size_t parse_options(int argc, char ** argv, uint16_t *rules_id) {
	int opt, optcount = 0;
	char * config_file;

	while ((opt = getopt(argc, argv, "c:lh")) != EOF) {
		switch (opt) {
		case 'c': 
			optcount++;
			if (optcount > 1) {
				usage(argv[0]);
			}
			config_file = optarg;
			break;
		case 'l':
			print_rules_info();
			exit( 0 );
		case 'h': 
		default: usage(argv[0]);
		}
	}
	mmt_sec_config_struct = get_mmt_sec_config(config_file);
	if (mmt_sec_config_struct==NULL)
	{
		fprintf(stderr, "Invalid configuration file: %s\n", config_file);
		exit(1);
	}
	return 0;
}

/**
 * Convert data encoded in a report to readable data that is either a double
 * or a string ending by '\0'.
 * This function will create a new memory segment to store its result.
 */

static inline void* _get_data_from_report( const report_t *report_node, message_element_t *me, int *type ){
	double number;
	char buffer[100], *new_string = NULL;
	const uint16_t buffer_size = 100;
	uint16_t size;
	uint8_t *data=NULL;
	int i=0;

	for (i=0; i<report_node->elements_count;i++){
		//mmt_debug("Report_node->report_elements[i].proto_id:%d. me->proto_id:%d", report_node->report_elements[i].proto_id, me->proto_id);
		//mmt_debug("report data %s", (unsigned char *)report_node->report_elements[i].data);
		if ((report_node->report_elements[i].proto_id==me->proto_id) && (report_node->report_elements[i].att_id==me->att_id)){
			//mmt_debug("Found the proto and att");
			data = (uint8_t *) report_node->report_elements[i].data;
			break;
		}
	}
	//mmt_debug("Not found the proto and att");
	//does not exist data for this proto_id and att_id
	if( data == NULL ) return NULL;
	//mmt_debug("Found data: %" PRIu8 "", data[0]);
	buffer[0] = '\0';

	//mmt_debug("me->proto_id: %d, me->att_id: %d", me->proto_id, me->att_id);
	//me->data_type = get_attribute_data_type(me->proto_id, me->att_id);
	//me->data_type = MMT_DATA_MAC_ADDR;

	switch( me->data_type ){
	case MMT_UNDEFINED_TYPE: /**< no type constant value */
		return NULL;
	case MMT_DATA_CHAR: /**< 1 character constant value */
	case MMT_U8_DATA: /**< unsigned 1-byte constant value */
		number = *data;
		*type = NUMERIC;
		return mmt_mem_dup( &number, sizeof( double ));
	case MMT_DATA_PORT: /**< tcp/udp port constant value */
	case MMT_U16_DATA: /**< unsigned 2-bytes constant value */
		number = *(uint16_t *) data;
		*type = NUMERIC;
		return mmt_mem_dup( &number, sizeof( double ));
	case MMT_U32_DATA: /**< unsigned 4-bytes constant value */
		number = *(uint32_t *) data;
		*type = NUMERIC;
		return mmt_mem_dup( &number, sizeof( double ));
	case MMT_U64_DATA: /**< unsigned 8-bytes constant value */
		number = *(uint64_t *) data;
		*type = NUMERIC;
		return mmt_mem_dup( &number, sizeof( double ));
	case MMT_DATA_FLOAT: /**< float constant value */
		number = *(float *) data;
		*type = NUMERIC;
		return mmt_mem_dup( &number, sizeof( double ));

	case MMT_DATA_MAC_ADDR: /**< ethernet mac address constant value */
		size = snprintf(buffer , buffer_size, "%02x:%02x:%02x:%02x:%02x:%02x", data[0], data[1], data[2], data[3], data[4], data[5] );
		//mmt_debug( "%d %s", size, buffer );
		*type = STRING;
		return mmt_mem_dup( buffer, size );
	case MMT_DATA_IP_NET: /**< ip network address constant value */
		break;
	case MMT_DATA_IP_ADDR: /**< ip address constant value */
		inet_ntop(AF_INET, data, buffer, buffer_size );
		//mmt_debug( "IPv4: %s", string );
		*type = STRING;
		return mmt_mem_dup( buffer, strlen( buffer));
	case MMT_DATA_IP6_ADDR: /**< ip6 address constant value */
		inet_ntop(AF_INET6, data, buffer, buffer_size );
		//mmt_debug( "IPv6: %s", string );
		*type = STRING;
		return mmt_mem_dup( buffer, strlen( buffer));

		//	    case MMT_DATA_POINTER: /**< pointer constant value (size is void *) */
		//	    case MMT_DATA_PATH: /**< protocol path constant value */
		//	    case MMT_DATA_TIMEVAL: /**< number of seconds and microseconds constant value */
		//	    case MMT_DATA_BUFFER: /**< binary buffer content */
		//
		//	    case MMT_DATA_POINT: /**< point constant value */
		//	    case MMT_DATA_PORT_RANGE: /**< tcp/udp port range constant value */
		//	    case MMT_DATA_DATE: /**< date constant value */
		//	    case MMT_DATA_TIMEARG: /**< time argument constant value */
		//	    case MMT_DATA_STRING_INDEX: /**< string index constant value (an association between a string and an integer) */
		//	    case MMT_DATA_LAYERID: /**< Layer ID value */
		//	    case MMT_DATA_FILTER_STATE: /**< (filter_id: filter_state) */
		//	    case MMT_DATA_PARENT: /**< (filter_id: filter_state) */
		//	    case MMT_STATS: /**< pointer to MMT Protocol statistics */
		//	   	 break;
	case MMT_BINARY_DATA: /**< binary constant value */
	case MMT_BINARY_VAR_DATA: /**< binary constant value with variable size given by function getExtractionDataSizeByProtocolAndFieldIds */
	case MMT_STRING_DATA: /**< text string data constant value. Len plus data. Data is expected to be '\0' terminated and maximum BINARY_64DATA_LEN long */
	case MMT_STRING_LONG_DATA: /**< text string data constant value. Len plus data. Data is expected to be '\0' terminated and maximum STRING_DATA_LEN long */
		*type = STRING;
		return mmt_mem_dup( ((mmt_binary_var_data_t *)data)->data, ((mmt_binary_var_data_t *)data)->len );
	case MMT_HEADER_LINE: /**< string pointer value with a variable size. The string is not necessary null terminating */
		return mmt_mem_dup( ((mmt_header_line_t *)data)->ptr, ((mmt_header_line_t *)data)->len );
	case MMT_STRING_DATA_POINTER: /**< pointer constant value (size is void *). The data pointed to is of type string with null terminating character included */
		*type = STRING;
		return mmt_mem_dup( data, strlen( (char*) data) );
	default:
		break;
	}
	return NULL;
}

/**
 * Convert a report (node) to a message being understandable by mmt-security.
 * The function returns NULL if the report contains no interested information.
 * Otherwise it creates a new memory segment to store the result message. One need
 * to use #free_message_t to free the message.
 */
static inline message_t* _report_to_msg( const report_t *report_node){
	size_t size, i, index;
	const proto_attribute_t **arr;
	bool has_data = NO;
	int type;
	void *data=NULL;
	message_t *msg = mmt_mem_alloc( sizeof ( message_t ) );

	msg->counter  = report_node->counter; //TODO

	//get a list of proto/attributes being used by mmt-security
	msg->timestamp = mmt_sec_encode_timeval(&report_node->timestamp);
	//mmt_debug("msg->timestamp: %lu", msg->timestamp);
	msg->elements_count = proto_atts_count;
	msg->elements       = mmt_mem_dup( proto_atts, proto_atts_count * sizeof( message_element_t));

	for( i=0; i<proto_atts_count; i++ ){
		data = _get_data_from_report(report_node, &proto_atts[i], &type);
		if( data != NULL ){
			//mmt_debug("has data = YES");
			has_data = YES;
			msg->elements[i].data      = data;
			msg->elements[i].data_type = type;
		}
	}

	//need to free #msg when the packet contains no-interested information
	if(likely(has_data))
	{
		//mmt_debug("has_data=YES, return msg");
		return msg;
	}
	free_message_t( msg );
	return NULL;
}



void signal_handler(int signal_type) {
	mmt_smp_sec_unregister( mmt_smp_sec_handler, NO );
	mmt_mem_free( rules_arr );
	mmt_mem_print_info();
	mmt_info( "Interrupted by signal %d", signal_type );
	exit( signal_type );
}

bool receiving_state(){
	int i;
	if (connectcnt==0) return YES;
	for (i=0; i<connectcnt; i++){
		if (recev_s[i]==YES) return YES;
	}
	return NO;
}
/*
void *processing_thr_rest (void *args){
mmt_smp_sec_handler_t *sec_handler = (mmt_smp_sec_handler_t *) args;
report_t *last;
while(thread_lock.count_str!=0){
						last = report_list->prev;
						if (pop_last(&report_list)==0) thread_lock.count_str--;
						report_handler(sec_handler, last);
						}
						gettimeofday(&end_t, NULL);
						fprintf(stderr, "\nExecution time = %d microseconds\n", time_diff(start_t, end_t));
pthread_exit((void *)NULL);
}
 */
void *receiving_thr (void *arg) {
	struct thr_r_arg_struct *thr_recv_struct = (struct thr_r_arg_struct *) arg;
	int sock = (intptr_t) thr_recv_struct->sock;
	int i = thr_recv_struct->index;
	recev_s[i] = YES;

	int n,on;
	int length=0;
	int total_length=0;
	uint8_t buffer[ REPORT_SIZE ]; //utf-8

	uint32_t length_of_report = 0;
	//int nb_rp_buff = 0;

	while(1){
		n = recv(sock, &length_of_report, 4, MSG_WAITALL);//Read 4 bytes first to know the length of the report
		if (n == 0)	break;
		if( length_of_report > REPORT_SIZE ){
			mmt_warn("Overflow: length_of_report = %d", length_of_report );
			length_of_report = REPORT_SIZE;
		}else if( length_of_report < 31 )
			continue;
		else if( length_of_report < 0 )
			mmt_info("Impossible len = %d", length_of_report );

		n = recv( sock, buffer, length_of_report-4, MSG_WAITALL );
		if( n == 0 ) break;
		if( n < 27 ) error("Report in bad format");
		length =0;
		if ((int) pthread_spin_lock(&thread_lock.spinlock_cr)) error("thread_lock.spinlock_cr failed");
		thread_lock.count_rcv++;
		pthread_spin_unlock(&thread_lock.spinlock_cr);

		int counter = 0;
		//mmt_debug("Report received, length=%d, thread_lock.count_rcv = %d \n", length_of_report, thread_lock.count_rcv);
		report_t *report_node;
		report_node = mmt_mem_alloc(sizeof(report_t));
		report_node->flag = 0;
		report_node->counter = 0; //TODO
		report_node->next = NULL;
		report_node->prev = NULL;
		report_node->elements_count=0;
		report_node->timestamp.tv_sec=0;
		report_node->timestamp.tv_usec=0;
		report_node->report_elements=NULL;

		memcpy(&report_node->elements_count,&buffer[length],1);
		length += 1;
		report_node->report_elements = mmt_mem_alloc(report_node->elements_count * sizeof(report_element_t));
		memcpy(&report_node->timestamp,&buffer[length],sizeof(struct timeval));
		//mmt_debug("Timestamp: %lu.%lu \n",report_node->timestamp.tv_sec, report_node->timestamp.tv_usec);
		length += sizeof (struct timeval);//16
		while((length_of_report- 4 -length) > 10){
			memcpy(&report_node->report_elements[counter].proto_id,&buffer[length],4);
			length += 4;
			memcpy(&report_node->report_elements[counter].att_id,&buffer[length],4);
			length += 4;
			memcpy(&report_node->report_elements[counter].data_len,&buffer[length],2);
			length += 2;
			report_node->report_elements[counter].data = mmt_mem_alloc(report_node->report_elements[counter].data_len);
			memcpy(report_node->report_elements[counter].data,&buffer[length],report_node->report_elements[counter].data_len);
			//unsigned char * data = (unsigned char*)report_node->report_elements[counter].data;
			//mmt_debug("report_node->elements_count = %d, proto_ID = %u. att_id = %u. data_len = %u. data = %02x, %02x\n", (int) report_node->elements_count, report_node->report_elements[counter].proto_id,
			//report_node->report_elements[counter].att_id,
			//report_node->report_elements[counter].data_len,
			//buffer[length], data[0]);
			length += report_node->report_elements[counter].data_len;
			counter++;
		}

		// Store the received report as a node
		//if (pthread_mutex_lock(&thread_lock.mutex_str)) error("pthread_mutex_lock failed");
		if(pthread_mutex_lock(&mutex)!=0) error("pthread_mutex_lock failed");
		while(!condition_v[i]) if (pthread_cond_wait(&cond[i], &mutex)!= 0) error("pthread_cond_wait failed");
		if (insert(&report_list, report_node)!= 0) error("Insert failed");
		thread_lock.count_str++;
		//if (thread_lock.count_str >= thr_recv_struct->threshold_size) { //|| time_diff(report_list->prev->timestamp, report_list->timestamp)>thr_recv_struct->threshold_time
		//if (pthread_cond_broadcast(&cond) != 0) error("pthread_cond_broadcast() error");//broadcast unlock mutex
		//}
		//pthread_mutex_unlock(&thread_lock.mutex_str);
		condition_v[i] = NO;
		pthread_cond_signal(&cond[i]);
		if(pthread_mutex_unlock(&mutex)!=0) error("pthread_mutex_unlock failed");
	}
	close(sock);
	if (pthread_mutex_lock(&thread_lock.mutex_recv_s)) error("pthread_mutex_lock failed");
	recev_s[i] = NO;
	receiv_s_glob = receiving_state();
	if (!receiv_s_glob){
		condition_v[i] = NO;
		pthread_cond_signal(&cond[i]);
		//if(!receiving_state()) if (pthread_cond_broadcast(&cond) != 0) error("pthread_cond_broadcast() error");//broadcast unlock mutex;
		//if (pthread_create(&thr_p_rest, NULL, processing_thr_rest,(void*) mmt_smp_sec_handler)) error("Can't create threads for processing the rest of buffer");
	}
	pthread_mutex_unlock(&thread_lock.mutex_recv_s);
	pthread_exit((void *)NULL);
}

int report_handler(void *args, report_t *last) {
	mmt_smp_sec_handler_t *sec_handler = (mmt_smp_sec_handler_t *) args;
	message_t *msg;
	if (last==NULL) return 1;
	msg =_report_to_msg(last);
	free_report_t(last);
	//mmt_debug("msg->timestamp: %lu", msg->timestamp);
	if(unlikely(msg == NULL)) return 1;
	mmt_smp_sec_process(sec_handler, msg);
	free_message_t( msg );
	return 0;
}

void *processing_thr (void *args) {
	struct thr_p_arg_struct *thr_proc_struct = (struct thr_p_arg_struct *) args;
	report_t * last = NULL;
	int nb_rp_buff=0;
	int i = thr_proc_struct->index;
	mmt_smp_sec_handler_t *sec_handler = thr_proc_struct->mmt_smp_sec_handl;

	while(notdone){
		if(pthread_mutex_lock(&mutex)!=0) error("pthread_mutex_lock failed");
		while(condition_v[i]) if (pthread_cond_wait(&cond[i], &mutex)!= 0) error("pthread_cond_wait failed");
		nb_rp_buff = thread_lock.count_str;
		if ((nb_rp_buff < mmt_sec_config_struct->threshold_size) && receiv_s_glob){
			condition_v[i] = YES;
			pthread_cond_signal(&cond[i]);
			if(pthread_mutex_unlock(&mutex)!=0) error("pthread_mutex_unlock failed");
			continue;
		}
		else { //start processing
			last = report_list->prev;
			if (pop_last(&report_list)==0) thread_lock.count_str--;
			condition_v[i] = YES;
			pthread_cond_signal(&cond[i]);
			if(pthread_mutex_unlock(&mutex)!=0) error("pthread_mutex_unlock failed");
			report_handler(sec_handler, last);
		}
		if(!receiv_s_glob){//break;
			while(thread_lock.count_str!=0){
				if(pthread_mutex_lock(&mutex)!=0) error("pthread_mutex_lock failed");
				last = report_list->prev;
				if (pop_last(&report_list)==0) thread_lock.count_str--;
				if(pthread_mutex_unlock(&mutex)!=0) error("pthread_mutex_unlock failed");
				report_handler(sec_handler, last);
			}
			gettimeofday(&end_t, NULL);
			fprintf(stderr, "\nExecution time = %d microseconds\n", time_diff(start_t, end_t));
			break;
		}
	}
	pthread_exit((void *)NULL);
}


int main(int argc, char** argv) {
	uint16_t *rules_id_filter;
	const proto_attribute_t **p_atts;
	uint32_t portno;
	uint8_t nb_thr_sec;

	int parentfd, childfd, i;

	char buffer[256];
	struct sockaddr_in serv_addr, cli_addr;
	struct thr_r_arg_struct thr_recv_arg;
	struct thr_p_arg_struct thr_proc_arg;
	int on;
	socklen_t socklen;
	fd_set readfds;

	on = 1;
	notdone = YES;
	recev_s[0] = YES;

	pthread_t thr_r[10];
	pthread_t thr_p[10];

	size_t size;
	thread_lock.count_rcv = 0;
	thread_lock.count_str = 0;

	parse_options(argc, argv, rules_id_filter);
	mmt_debug("%u.%u.%u.%u", mmt_sec_config_struct->nb_thr_sec, mmt_sec_config_struct->portno, mmt_sec_config_struct->threshold_size, mmt_sec_config_struct->threshold_time);
	portno = mmt_sec_config_struct->portno;
	nb_thr_sec = mmt_sec_config_struct->nb_thr_sec;
	thr_recv_arg.threshold_size = mmt_sec_config_struct->threshold_size;
	thr_recv_arg.threshold_time = mmt_sec_config_struct->threshold_time;
	/*
		signal(SIGINT,  signal_handler);
		signal(SIGTERM, signal_handler);
		signal(SIGSEGV, signal_handler);
		signal(SIGABRT, signal_handler);
	 */

	//pthread_spin_init(&thread_lock.spinlock_cs, 0);
	pthread_spin_init(&thread_lock.spinlock_cr, 0);
	pthread_mutex_init(&thread_lock.mutex_str, 0);
	pthread_spin_init(&thread_lock.spinlock_processing, 0);
	pthread_mutex_init(&thread_lock.mutex_recv_s, 0);
	if (pthread_mutex_init(&mutex, NULL) != 0) error("pthread_mutex_init() error");


	//get all available rules
	size = mmt_sec_get_rules_info( &rules_arr );
	//init mmt-sec to verify the rules
	mmt_smp_sec_handler = mmt_smp_sec_register( rules_arr, size, nb_thr_sec, print_verdict, NULL );

	//register protocols and their attributes using by mmt-sec
	size = mmt_smp_sec_get_unique_protocol_attributes( mmt_smp_sec_handler, &p_atts );
	proto_atts_count = size;

	proto_atts = mmt_mem_alloc( size * sizeof( message_element_t ));
	for( i=0; i<size; i++ ){
		//mmt_debug("p_atts[i]->proto_id = %d, p_atts[i]->att_id: %d", p_atts[i]->proto_id, p_atts[i]->att_id);
		proto_atts[i].proto_id  = p_atts[i]->proto_id;
		proto_atts[i].att_id    = p_atts[i]->att_id;
		proto_atts[i].data_type = get_attribute_data_type( p_atts[i]->proto_id, p_atts[i]->att_id );
		//mmt_debug("p_atts[i]->proto_id = %u, p_atts[i]->att_id = %u, proto_atts[i].data_type = %d", p_atts[i]->proto_id, p_atts[i]->att_id, proto_atts[i].data_type);
	}
	/*Create here threads for reading and processing the stored reports after a suitable delay (in terms of buffer size and timestamp)
	 * to make the reordering task makes sense.
	 *
	 */
	/*for (i=0; i<nbr_thr_p; i++){
				if (pthread_create(&thr_p[nbr_thr_p], NULL, processing_thr,(void*) mmt_smp_sec_handler)) error("Can't create threads for processing");
				}
	 */
	/* First call to socket() function */
	parentfd = socket(AF_INET, SOCK_STREAM, 0);

	if( parentfd < 0) error("ERROR opening socket");

	if (setsockopt( parentfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) )<0)
		error("setsockopt(SO_REUSEADDR) failed");

	/* Initialize socket structure */
	bzero((char *) &serv_addr, sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(portno);

	/* Now bind the host address using bind() call.*/
	if (bind(parentfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) error("ERROR on binding");
	//bind says to the system : okay, from now on, any packet with destination {address->sun_addr} should be forwarded to my socket_fd, so I can read them


	/* Now start listening for the clients, here
	 * process will go in sleep mode and will wait
	 * for the incoming connection
	 */
	listen(parentfd, 5);//int listen(int socket, int backlog);  limit the number of outstanding connections in the socket's listen queue

	socklen = sizeof(cli_addr);

	printf("Server is running\n");
	/*
	 * Loop: wait for connection request or stdin command.
	 * If connection request, then create a thread for each connection for receiving the report.
	 * If command, then process command.
	 */
	while (notdone) {
		/*
		 * select: Has the user typed something to stdin or
		 * has a connection request arrived?
		 */
		FD_ZERO(&readfds);          /* initialize the fd set */
		FD_SET(parentfd, &readfds); /* add socket fd */
		FD_SET(0, &readfds);        /* add stdin fd (0) */
		if (select(parentfd+1, &readfds, 0, 0, 0) < 0) {
			error("ERROR in select");
		}

		/* if the user has entered a command, process it */
		if (FD_ISSET(0, &readfds)) {
			if(fgets(buffer, 256, stdin))
				switch (buffer[0]) {
				case 'i': /* print the connection cnt */
					printf("Received %d connection requests so far.\n", connectcnt);
					printf("Type i for printing the number of connections, q for quitting\n");
					printf("server> ");
					fflush(stdout);
					break;
				case 'q': /* terminate the server */
					notdone = NO;
					break;
				default: /* bad input */
					printf("ERROR: unknown command. Type i for printing the number of connections, q for quitting\n");
					printf("server> ");
					fflush(stdout);
				}
		}

		/* if a connection request has arrived, process it */
		if (FD_ISSET(parentfd, &readfds)) {
			/*
			 * accept: wait for a connection request
			 */
			childfd = accept(parentfd,
					(struct sockaddr *) &cli_addr, &socklen);
			if (childfd < 0) error("ERROR on accept");
			thr_recv_arg.sock = (intptr_t) childfd;
			thr_recv_arg.index = connectcnt;
			// To calculate execution time
			if (connectcnt==0)gettimeofday(&start_t, NULL);
			if (pthread_create(&thr_r[connectcnt], NULL, receiving_thr,(void*) &thr_recv_arg)) error("Can't create threads for reading");
			thr_proc_arg.mmt_smp_sec_handl = mmt_smp_sec_handler;
			thr_proc_arg.index = connectcnt;
			condition_v[connectcnt] = NO;
			if (pthread_cond_init(&cond[connectcnt], NULL) != 0) error("pthread_cond_init() error");
			if (pthread_create(&thr_p[connectcnt], NULL, processing_thr,(void*) &thr_proc_arg)) error("Can't create threads for processing");
			connectcnt++;
			//mmt_debug("Created receiving thread with thr_recv_arg.index =%d", thr_recv_arg.index);
			//if(connectcnt==1){if (pthread_cond_broadcast(&cond) != 0) error("pthread_cond_broadcast() error");}
		}
	}
	printf("Terminating server.\n");
	fprintf(stderr, "\nExecution time = %d microseconds\n", time_diff(start_t, end_t));
	printf("Nb of reports received: %d\n", thread_lock.count_rcv);
	printf("Nb of reports lost: %d\n", thread_lock.count_str);
	close(parentfd);

	//free resources using by mmt-sec
	mmt_smp_sec_unregister( mmt_smp_sec_handler, NO);
	mmt_mem_free( rules_arr );
	mmt_mem_free( proto_atts );
	free(mmt_sec_config_struct);
	//free report buffer
	//mmt_mem_free(report_list->report_elements);
	//mmt_mem_free(report_list);

	///free resources using by mmt-sec
	mmt_mem_print_info();
	return EXIT_SUCCESS;
}
