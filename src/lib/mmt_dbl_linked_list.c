/*
 * data_struct.c
 *
 *  Created on: 26 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include <string.h>
#include "mmt_lib.h"

///////////////////////////////////////Linked-list////////////////////////////////////////////
/** Public API */
inline link_node_t *create_node_of_link_list( void *data ){
	link_node_t *new_node = mmt_mem_alloc( sizeof( link_node_t ));
	new_node->data = data;
	new_node->prev = new_node->next = NULL;
	return new_node;
}

/** Public API */
link_node_t *append_node_to_link_list( link_node_t *head, void *data ){
	link_node_t *new_node, *ptr;

	new_node = create_node_of_link_list( data );

	if( unlikely( head == NULL )) return new_node;

	//append to tail
	ptr = head;
	//find tail
	while( ptr->next != NULL ) ptr = ptr->next;
	//add new node to tail
	ptr->next = new_node;
	new_node->prev = ptr;

	return head;
}

/** Public API */
link_node_t *insert_node_to_link_list( link_node_t *head, void *data ){
	link_node_t *new_node;

	new_node = create_node_of_link_list( data );

	if( unlikely( head == NULL )) return new_node;

	//insert to head
	new_node->next = head;
	head->prev     = new_node;

	return new_node;
}

void free_link_list( link_node_t *head, bool free_data ){
	link_node_t *ptr;
	while( head != NULL ){
		if( free_data )
			mmt_mem_free( head->data );
		ptr = head->next;
		head->next = head->prev = NULL;
		mmt_mem_free( head );

		head = ptr;
	}
}

void free_link_list_and_data( link_node_t *head, void (*free_fn)( void *) ){
	link_node_t *ptr;
	while( head != NULL ){
		if( free_fn )
			free_fn( head->data );
		ptr = head->next;
		head->next = head->prev = NULL;
		mmt_mem_free( head );

		head = ptr;
	}
}


link_node_t *remove_node_from_link_list( link_node_t *head, const void *data ){
	link_node_t *ptr = head;
	while( ptr != NULL && ptr->data != data )
		ptr = ptr->next;

	//not found any node having this #data
	if( ptr == NULL )
		return head;

	if( ptr == head ){
		head = head->next;
		if( head != NULL )
			head->prev = NULL;
		//free this node
		mmt_mem_free( ptr );
		return head;
	}
	//ptr is not null && ptr->pre is not null as ptr != head
	ptr->prev->next = ptr->next;

	if( ptr->next != NULL )
		ptr->next->prev = ptr->prev;

	//free this node
	mmt_mem_free( ptr );

	return head;
}

