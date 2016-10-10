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

#include <string.h>
#include "base.h"
#include "mmt_log.h"

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

void free_link_list( link_node_t *head, enum bool free_data );

////////////////////////Binary-Tree map////////////////////////////////////////////////
/**
 * We implement a generic map on top of a binary-tree.
 * A map is a set of key-value in which each key is unique.
 *	A key and a value can be anything.
 *	One need to provide a function to compare 2 keys, such as strcmp to compare 2 strings.
 */
enum compare_result {CMP_LESS = -1, CMP_EQUAL = 0, CMP_GREATER = 1};

static inline int compare_string( const void *a, const void *b ){
	return strcmp( (char *)a, (char *)b );
}
/**
 * Integer comparison
 */
/**
 * Public API
 */
static inline int compare_uint8_t( const void *a, const void *b){
	mmt_assert( a != NULL && b != NULL, "NULL values in compare_uint8_t function %s:%d", __FILE__, __LINE__ );
	return *(uint8_t *)a - *(uint8_t *)b;
}
static inline int compare_uint16_t( const void *a, const void *b){
	mmt_assert( a != NULL && b != NULL, "NULL values in compare_uint16_t function %s:%d", __FILE__, __LINE__ );
	return *(uint16_t *)a - *(uint16_t *)b;
}
static inline int compare_uint32_t( const void *a, const void *b){
	mmt_assert( a != NULL && b != NULL, "NULL values in compare_uint32_t function %s:%d", __FILE__, __LINE__ );
	return *(uint32_t *)a - *(uint32_t *)b;
}
static inline int compare_uint64_t( const void *a, const void *b){
	mmt_assert( a != NULL && b != NULL, "NULL values in compare_uint64_t function %s:%d", __FILE__, __LINE__ );
	return *(uint64_t *)a - *(uint64_t *)b;
}
/**
 * Binary map structure
 */
typedef void *mmt_map_t;

/**
 * Create and init a binary map
 * - Input:
 * 	+ fun: a function pointer, e.g, strcmp. This function is used to compare keys.
 * 		It takes two parameters being 2 keys to compare.
 * 		It must return:
 * 			- 0 if they are equal
 * 			- -1 if the first key is less than the second
 * 			- 1 if the first key is greater than the second
 * - Output
 * - Return
 * 	+ A pointer points to a binary map
 */
mmt_map_t *mmt_map_init( int (*fun)(const void*, const void*) );
/**
 * Set data to a key
 * - Input:
 * 	+ map: the map to be modified
 * 	+ key : the key of data
 * 	+ data: data to set to the key
 * 	+ override_if_exist: decide to override the old value by the new one
 * - Output
 * - Return:
 * 	+ NULL if no key exists
 * 	+ Pointer points to:
 * 		- the data being overridden if "override_if_exist" = TRUE,
 * 		- otherwise, the parameter "data"
 * - Note:
 * 	+ "key" and "data" should be created by mmt_malloc/mmt_mem_dup. This allows mmt_map_free to free them.
 * 		If not, you must use mmt_map_free( map, NO) to free only map, that does not free keys-data.
 * 	+ when the function return a no-null pointer, to avoid memory leak, one should:
 * 		- free the parameter "key"
 * 		- free the return pointer
 */
void * mmt_map_set_data( mmt_map_t *map, void *key, void *data, enum bool override_if_exist );
/**
 * Get data of a key
 * - Input:
 * 	+ map:
 * 	+ key
 * - Return:
 * 	+ a pointer points to data having key if exist, otherwise NULL
 */
void *mmt_map_get_data( const mmt_map_t *map, const void *key );

/**
 * free the map and its keys-data
 */
void mmt_map_free( mmt_map_t *map, enum bool free_data );

/**
 * Get number of elements in the map
 */
size_t mmt_map_count( const mmt_map_t *map );

/**
 * Iterate a map
 * Input:
 * 	+ map to iterate
 * 	+ an iterate function having 3 parameters:
 * 		- key
 * 		- data
 * 		- user_data is the "user_data" parameter
 * 		- index
 * 		- total
 * 	+ user_data
 */
void mmt_map_iterate( const mmt_map_t *map, void (*map_iterate_function)( void *key, void *data, void *user_data, size_t index, size_t total ), void *user_data );

size_t mmt_map_get_data_array( const mmt_map_t *map, void **array);

#endif /* SRC_LIB_DATA_STRUCT_H_ */
