/*
 * data_struct.c
 *
 *  Created on: 26 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */


#include "data_struct.h"
#include "mmt_log.h"
#include "mmt_alloc.h"

/** Public API */
link_node_t *create_node_of_link_list( void *data ){
	link_node_t *new_node = mmt_malloc( sizeof( link_node_t ));
	new_node->data = data;
	new_node->prev = new_node->next = NULL;
	return new_node;
}

/** Public API */
link_node_t *append_node_to_link_list( link_node_t *head, void *data ){
	link_node_t *new_node, *ptr;

	new_node = create_node_of_link_list( data );

	if( head == NULL )
		return new_node;

	//append to tail
	ptr = head;
	//find tail
	while( ptr->next != NULL ) ptr = ptr->next;
	//add new node to tail
	ptr->next = new_node;
	new_node->prev = ptr;

	return head;
}
