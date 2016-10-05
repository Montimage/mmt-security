/*
 * data_struct.c
 *
 *  Created on: 26 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */


#include "data_struct.h"
#include "mmt_log.h"
#include "mmt_alloc.h"

///////////////////////////////////////Linked-list////////////////////////////////////////////
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



///////////////////////////////////////MMT-Map////////////////////////////////////////////
/**
 * Implement a map by a binary-tree
 */
typedef struct mmt_map_node_struct{
	struct mmt_map_node_struct *left, *right;
	void *key, *data;
}_mmt_map_node_t;
typedef struct mmt_map_struct{
	_mmt_map_node_t *root;
	int (*compare_function)(const void*, const void*);
	//number of nodes in the map
	uint64_t size;
}_mmt_map_t;

/**
 * Public API
 */
size_t mmt_map_count( const mmt_map_t *map ){
	if( map == NULL ) return 0;
	return ((_mmt_map_t*) map)->size;
}

/**
 * Public API
 */
mmt_map_t *mmt_map_init( int (*fun)(const void*, const void*) ){
	_mmt_map_t *map = mmt_malloc( sizeof( _mmt_map_t ));
	map->compare_function = fun;
	map->root = NULL;
	map->size = 0;
	return (mmt_map_t)map;
}

void _mmt_map_free_node( _mmt_map_node_t *node, enum bool free_data ){
	if( node == NULL ) return;
	//free its key-data if need
	if( free_data == YES ){
		mmt_free_and_assign_to_null( node->key );
		mmt_free_and_assign_to_null( node->data );
	}
	//free its children
	if( node->left != NULL )
		_mmt_map_free_node( node->left, free_data );
	if( node->right != NULL )
		_mmt_map_free_node( node->right, free_data );

	node->left = node->right = NULL;

	//free the node itself
	mmt_free( node );
}

/**
 * Public API
 */
void mmt_map_free( mmt_map_t *map, enum bool free_data  ){
	if( map == NULL ) return;
	_mmt_map_t *_tree = (_mmt_map_t*) map;
	_mmt_map_free_node( _tree->root, free_data );
	mmt_free( map );
}


void* _mmt_map_set_data( int (*fun)(const void*, const void*), _mmt_map_node_t **node, void *key, void *data, enum bool override_if_exist ){
	enum compare_result ret = 0;
	void *ptr = NULL;
	_mmt_map_node_t *node_ptr = *node;

	if( node_ptr == NULL ){
		node_ptr = mmt_malloc( sizeof( _mmt_map_node_t ));
		node_ptr->left = node_ptr->right = NULL;
		node_ptr->key  = key;
		node_ptr->data = data;
		*node = node_ptr;
		return NULL;
	}

	ret = (*fun)( key, node_ptr->key );
	//this node has the same key
	if( ret == 0 ){
		if( override_if_exist ){
			ptr = node_ptr->data;
			node_ptr->data = data;
			return ptr;
		} else
			return data;
	}else if( ret < 0 )
		return _mmt_map_set_data( fun, &(node_ptr->left), key, data, override_if_exist );
	else
		return _mmt_map_set_data( fun, &(node_ptr->right), key, data, override_if_exist );
}

/**
 * Public API
 */
void* mmt_map_set_data( mmt_map_t *map, void *key, void *data, enum bool override_if_exist ){
	void *ptr;
	if( map == NULL || key == NULL || data == NULL ) return NULL;
	_mmt_map_t *_tree = (_mmt_map_t*) map;
	ptr = _mmt_map_set_data( _tree->compare_function, &(_tree->root), key, data, override_if_exist );
	//successfully inserted ==> increase number of nodes
	if( ptr == NULL ) _tree->size ++;
	return ptr;
}


void *_mmt_map_get_data( int (*fun)(const void*, const void*), _mmt_map_node_t *node, const void *key ){
	if( node == NULL ) return NULL;
	enum compare_result ret = (*fun)( key, node->key );
	//this node has the same key
	if( ret == 0 )
		return node->data;
	else if( ret < 0 ){
		if( node->left != NULL )
			return _mmt_map_get_data( fun, node->left, key );
	}else{
		if( node->right != NULL )
			return _mmt_map_get_data( fun, node->right, key );
	}
	return NULL;
}

/**
 * Public API
 */
void *mmt_map_get_data( const mmt_map_t *map, const void *key ){
	if( map == NULL || key == NULL ) return NULL;
	_mmt_map_t *_tree = (_mmt_map_t*) map;
	if( _tree->root == NULL ) return NULL;

	return _mmt_map_get_data( _tree->compare_function, _tree->root, key );
}


void _mmt_map_node_iterate( const _mmt_map_node_t *node, void (*map_iterate_function)( void *_key, void *_data, void *_user_data, size_t _index, size_t _total ), void *user_data, size_t *index, size_t total ){
	if( node->left != NULL )
		_mmt_map_node_iterate( node->left, map_iterate_function, user_data, index, total );
	(*map_iterate_function)( node->key, node->data, user_data, *index, total );
	//is not the first running of map_iterate_function
	(*index) ++;
	if( node->right != NULL )
		_mmt_map_node_iterate( node->right, map_iterate_function, user_data, index, total );
}
/**
 * Public API
 */
void mmt_map_iterate( const mmt_map_t *map, void (*map_iterate_function)( void *key, void *data, void *user_data, size_t index, size_t total ), void *user_data ){
	size_t index = 0;
	if( map == NULL ) return;
	_mmt_map_t *_tree = (_mmt_map_t*) map;
	if( _tree->root == NULL ) return;
	_mmt_map_node_iterate( _tree->root, map_iterate_function, user_data, &index, _tree->size );
}
