/*
 * data_struct.h
 *
 *  Created on: 20 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 * Basic data structure: linked-list, binary_stree
 */

#ifndef SRC_LIB_DATA_STRUCT_H_
#define SRC_LIB_DATA_STRUCT_H_

#include "base.h"
//////////link list ///////////////
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



/////////////Array//////////////////
typedef struct array_struct{
	size_t size;
	void **data;
} array_t;

////////////Binary Tree////////////
typedef struct binary_tree_node_struct{
	void *data;
	struct binary_tree_node_struct *left, *right, *parent;
}binary_tree_node_t;

typedef struct binary_tree_struct{
	binary_tree_node_t *root, **node_list;
}binary_tree_t;

#endif /* SRC_LIB_DATA_STRUCT_H_ */
