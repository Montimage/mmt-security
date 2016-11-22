/*
 * data_struct.h
 *
 *  Created on: 20 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 * Basic data structure: linked-list, binary_stree
 */

#ifndef SRC_LIB_MMT_DBL_LINKED_LIST_H_
#define SRC_LIB_MMT_DBL_LINKED_LIST_H_

#include <stdint.h>
#include "base.h"
//////////////////////////////////Linked-List ///////////////////////////////////////
typedef struct link_node_struct{
	/** two linkers link to the previous and the next nodes*/
	struct link_node_struct *prev, *next;
	/** data of the node */
	void *data;
}link_node_t;

/**
 * Create a new node of a linked-list
 * - Input:
 * 	+ *data: a pointer points to data of the node being created
 * - Output:
 * - Return:
 * 	+ a pointer points to the new node
 */
link_node_t *create_node_of_link_list( void *data );

/**
 * Create then append a new node to the end of a linked-list
 * - Input:
 * 	+ entry: head of the linked-list. This can be NULL
 * 	+ data : data to be add to the new node
 * - Output:
 * - Return:
 * 	+ new head of the linked-list.
 * 		If entry is NULL then the function will return the new node being created
 */
link_node_t *append_node_to_link_list( link_node_t *entry, void *data );
link_node_t *insert_node_to_link_list( link_node_t *entry, void *data );

/**
 * Remove a node having #data from the list.
 * If there is no node has #data, the function does not change the list.
 */
link_node_t *remove_node_from_link_list( link_node_t *entry, const void *data );

/**
 * Free a list.
 * Data of each node is freed if #free_data == YES
 */
void free_link_list( link_node_t *head, bool free_data );

/**
 * Free a list and its data.
 * Data of each node is freed by function #free_fn.
 * If #free_fn is NULL, the data will not be freed.
 */
void free_link_list_and_data( link_node_t *head, void (*free_fn)( void *) );

static inline size_t count_nodes_from_link_list( const link_node_t *entry ){
	size_t size = 0;
	while( entry != NULL ){
		size ++;
		entry = entry->next;
	}
	return size;
}


#endif /* SRC_LIB_MMT_DBL_LINKED_LIST_H_ */
