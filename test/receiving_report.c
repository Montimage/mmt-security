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
#include "../src/lib/mmt_lib.h"
#include "../src/lib/mmt_smp_security.h"
#include "../src/dpi/mmt_dpi.h"
#include "../src/dpi/types_defs.h"
#include "../src/lib/config.h"

#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif

struct timeval start_t, end_t;

static message_element_t *proto_atts = NULL;
static int connectcnt = 0;

static bool notdone; //use notdone to terminate the server
static mmt_sec_config_struct_t *mmt_sec_config_struct;

typedef struct report_element {
	uint32_t proto_id;
	uint32_t att_id;
	uint16_t data_len;
	void *data;
} report_element_t;

typedef struct report {
	int flag;
	int counter;
	size_t elements_count;
	struct timeval timestamp;
	report_element_t *report_elements;
	struct report * next;
	struct report * prev;
} report_t;
static struct report *report_list = NULL;

struct arg_struct {
	int sock;
	int index;
	uint16_t threshold_size;
	uint16_t threshold_time;
};

struct {
	pthread_spinlock_t spinlock_cr; //lock to count the reports received
	pthread_spinlock_t spinlock_processing; //lock for processing threads
	pthread_spinlock_t spinlock_r; //lock to insert the reports
	pthread_spinlock_t spinlock_recv_s; //lock for determining receiving state = YES/NO
	int count_str; //count the reports stored
	int count_rcv; //count the reports received
} thread_lock;
pthread_cond_t cond;
pthread_mutex_t mutex;

void error(const char *msg) {
	perror(msg);
	exit(1);
}

int time_diff(struct timeval t1, struct timeval t2) {
	return (((t2.tv_sec - t1.tv_sec) * 1000000) + (t2.tv_usec - t1.tv_usec));
}

int timevalcmp(struct timeval tv1, struct timeval tv2) {
	if ((int) tv1.tv_sec > (int) tv2.tv_sec) return 1;
	if (((int) tv1.tv_sec == (int) tv2.tv_sec) && ((int) tv1.tv_usec > (int) tv2.tv_usec)) return 1;
	return 0;
}

int free_report_t(report_t *node) {
	int i;
	if (node == NULL) return 1; //nothing to do
	for (i = 0; i < node->elements_count; i++) {
		mmt_mem_free(node->report_elements[i].data);
	}
	mmt_mem_free(node->report_elements);
	mmt_mem_free(node);
	return 0;
}

/*Pop/Delete last node (FIFO-Queue)*/
int pop_last(report_t **head) {
	int i;
	report_t * last;
	/*Only one node*/
	if (thread_lock.count_str == 0) return 1;
	if (thread_lock.count_str == 1) { //one node
		free_report_t(*head);
		*head = NULL;
		return 0;
	}
	if (thread_lock.count_str == 2) { //2 nodes
		last = (*head)->next;
		(*head)->next = NULL;
		(*head)->prev = *head;
		free_report_t(last);
		return 0;
	}
//more than 2 nodes
	last = (*head)->prev;
	last->prev->next = NULL;
	(*head)->prev = last->prev;
	free_report_t(last);
	return 0;
}

/*Insert a new node to the double linked list that was
 * in good order of data*/

int insert(report_t **head, report_t *report_node) {
	report_t * current, *temp;

	// The list is empty
	if (thread_lock.count_str == 0) {
		//mmt_debug("Add the first node\n");
		*head = report_node;
		(*head)->prev = report_node; //if the node has only one node, head->prev = head; head->next = NULL
		(*head)->next = NULL;
		return 0;
	}

	// The list contains only one node
	if (thread_lock.count_str == 1) {
		if (timevalcmp((*head)->timestamp, report_node->timestamp) == 0) { //add to the beginning
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
	while ((timevalcmp(current->timestamp, report_node->timestamp))
			&& (current->next != NULL)) {
		current = current->next;
	}
	if (current == *head) { //timestamp is bigger than the first node, add to the beginning
		//mmt_debug("At least two nodes. Add to the beginning\n");
		temp = report_node;
		temp->next = *head;
		temp->prev = (*head)->prev;
		(*head)->prev = temp;
		*head = temp;
		return 0;
	}
	if (current->next == NULL) {
		if (timevalcmp(current->timestamp, report_node->timestamp) == 1) {//add to the end
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
void print_list(report_t *head) {
	report_t * current = head;
	while (current != NULL) {
		printf("Timestamp: %lu.%lu", current->timestamp.tv_sec,
				current->timestamp.tv_usec);
		current = current->next;
		printf("\n");
	}
}

void usage(const char * prg_name) {
	fprintf(stderr, "%s [<option>]\n", prg_name);
	fprintf(stderr, "Option:\n");
	fprintf(stderr, "\t-c <config file>: Start MMT-SEC server\n");
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
		case 'h':
		default:
			usage(argv[0]);
		}
	}
	mmt_sec_config_struct = get_mmt_sec_config(config_file);
	if (mmt_sec_config_struct == NULL) {
		fprintf(stderr, "Invalid configuration file: %s\n", config_file);
		exit(1);
	}
	return 0;
}

void *receiving_thr(void *arg) {
	struct arg_struct *thr_recv_struct = (struct arg_struct *) arg;
	int sock = (intptr_t) thr_recv_struct->sock;
	int i = thr_recv_struct->index;

	int n, on;
	int length = 0;
	int total_length = 0;
	unsigned char buffer[256];
	unsigned char length_buffer[4];

	int length_of_report = 0;
	report_t *last_node;

	while (1) {
		bzero(length_buffer, 4);
		n = recv(sock, length_buffer, 4, MSG_WAITALL);//Read 4 bytes first to know the length of the report

		if (n < 0) {
			error("ERROR reading from socket");
		}

		if (n < 4) break;
		memcpy(&length_of_report, &length_buffer, 4);

		bzero(buffer, 256);

		if (length_of_report > 1000 || length_of_report < 30) continue; //1000 = maximum size of the report 30 = size of timeval (16) + 4 + 10

		bzero(buffer, 256);
		n = recv(sock, buffer, length_of_report - 4, MSG_WAITALL); //Read the report
		if (n < 0) error("ERROR reading from socket");
		buffer[n] = '\0';
		length = 0;

		if ((int) pthread_spin_lock(&thread_lock.spinlock_cr)) error(
				"thread_lock.spinlock_cr failed");
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
		report_node->elements_count = 0;
		report_node->timestamp.tv_sec = 0;
		report_node->timestamp.tv_usec = 0;
		report_node->report_elements = NULL;

		memcpy(&report_node->elements_count, &buffer[length], 1);
		length += 1;
		report_node->report_elements = mmt_mem_alloc(
				report_node->elements_count * sizeof(report_element_t));
		memcpy(&report_node->timestamp, &buffer[length], sizeof(struct timeval));
		//mmt_debug("Timestamp: %lu.%lu \n",report_node->timestamp.tv_sec, report_node->timestamp.tv_usec);
		length += sizeof(struct timeval); //16
		while ((length_of_report - 4 - length) > 10) {
			memcpy(&report_node->report_elements[counter].proto_id,
					&buffer[length], 4);
			length += 4;
			memcpy(&report_node->report_elements[counter].att_id, &buffer[length],
					4);
			length += 4;
			memcpy(&report_node->report_elements[counter].data_len,
					&buffer[length], 2);
			length += 2;
			report_node->report_elements[counter].data = mmt_mem_alloc(
					report_node->report_elements[counter].data_len);
			memcpy(report_node->report_elements[counter].data, &buffer[length],
					report_node->report_elements[counter].data_len);
			//unsigned char * data = (unsigned char*)report_node->report_elements[counter].data;
			//mmt_debug("report_node->elements_count = %d, proto_ID = %u. att_id = %u. data_len = %u. data = %02x, %02x\n", (int) report_node->elements_count, report_node->report_elements[counter].proto_id,
			//report_node->report_elements[counter].att_id,
			//report_node->report_elements[counter].data_len,
			//buffer[length], data[0]);
			length += report_node->report_elements[counter].data_len;
			counter++;
		}

		// Store the received report as a node
		if (pthread_spin_lock(&thread_lock.spinlock_r)) error(
				"pthread_spin_lock failed");
		if (insert(&report_list, report_node) != 0) error("Insert failed");
		thread_lock.count_str++;
		if (thread_lock.count_str > mmt_sec_config_struct->threshold_size) {
			print_list(report_list->prev);
			if (pop_last(&report_list) == 0) thread_lock.count_str--;
		}
		pthread_spin_unlock(&thread_lock.spinlock_r);
	}
	close(sock);
	pthread_exit((void *) NULL);
}

int main(int argc, char** argv) {
	uint32_t portno;
	uint8_t nb_thr_sec;
	uint16_t *rules_id_filter;

	int parentfd, childfd, i;

	char buffer[256];
	struct sockaddr_in serv_addr, cli_addr;
	struct arg_struct thr_recv_arg;
	int on;
	socklen_t socklen;
	fd_set readfds;

	on = 1;
	notdone = YES;

	pthread_t thr_r[10];

	size_t size;
	thread_lock.count_rcv = 0;
	thread_lock.count_str = 0;

	parse_options(argc, argv, rules_id_filter);
	portno = mmt_sec_config_struct->portno;
	nb_thr_sec = mmt_sec_config_struct->nb_thr_sec;
	thr_recv_arg.threshold_size = mmt_sec_config_struct->threshold_size;
	thr_recv_arg.threshold_time = mmt_sec_config_struct->threshold_time;

	pthread_spin_init(&thread_lock.spinlock_cr, 0);
	pthread_spin_init(&thread_lock.spinlock_r, 0);

	/* First call to socket() function */
	parentfd = socket(AF_INET, SOCK_STREAM, 0);

	if (parentfd < 0) error("ERROR opening socket");

	if (setsockopt(parentfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) error(
			"setsockopt(SO_REUSEADDR) failed");

	/* Initialize socket structure */
	bzero((char *) &serv_addr, sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(portno);

	/* Now bind the host address using bind() call.*/
	if (bind(parentfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) error(
			"ERROR on binding");
	//bind says to the system : okay, from now on, any packet with destination {address->sun_addr} should be forwarded to my socket_fd, so I can read them

	/* Now start listening for the clients, here
	 * process will go in sleep mode and will wait
	 * for the incoming connection
	 */
	listen(parentfd, 5);	//int listen(int socket, int backlog);  limit the number of outstanding connections in the socket's listen queue

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
		FD_ZERO(&readfds); /* initialize the fd set */
		FD_SET(parentfd, &readfds); /* add socket fd */
		FD_SET(0, &readfds); /* add stdin fd (0) */
		if (select(parentfd + 1, &readfds, 0, 0, 0) < 0) {
			error("ERROR in select");
		}

		/* if the user has entered a command, process it */
		if (FD_ISSET(0, &readfds)) {
			if (fgets(buffer, 256, stdin)) switch (buffer[0]) {
			case 'i': /* print the connection cnt */
				printf("Received %d connection requests so far.\n", connectcnt);
				printf(
						"Type i for printing the number of connections, q for quitting\n");
				printf("server> ");
				fflush(stdout);
				break;
			case 'q': /* terminate the server */
				notdone = NO;
				break;
			default: /* bad input */
				printf(
						"ERROR: unknown command. Type i for printing the number of connections, q for quitting\n");
				printf("server> ");
				fflush(stdout);
			}
		}

		/* if a connection request has arrived, process it */
		if (FD_ISSET(parentfd, &readfds)) {
			/*
			 * accept: wait for a connection request
			 */
			childfd = accept(parentfd, (struct sockaddr *) &cli_addr, &socklen);
			if (childfd < 0) error("ERROR on accept");
			thr_recv_arg.sock = (intptr_t) childfd;
			thr_recv_arg.index = connectcnt;
			// To calculate execution time
			//if (connectcnt==0)gettimeofday(&start_t, NULL);
			if (pthread_create(&thr_r[connectcnt], NULL, receiving_thr,
					(void*) &thr_recv_arg)) error(
					"Can't create threads for reading");
			connectcnt++;
		}
	}
	printf("Terminating server.\n");
	while (thread_lock.count_str != 0) {
		print_list(report_list->prev);
		if (pop_last(&report_list) == 0) thread_lock.count_str--; //free the rest of the report_list
	}
	//fprintf(stderr, "\nExecution time = %d microseconds\n", time_diff(start_t, end_t));
	printf("Nb of reports received: %d\n", thread_lock.count_rcv);
	printf("Nb of reports lost: %d\n", thread_lock.count_str);
	close(parentfd);

	//free resources using by mmt-sec
	free(mmt_sec_config_struct);

	///free resources using by mmt-sec
	mmt_mem_print_info();
	return EXIT_SUCCESS;
}
