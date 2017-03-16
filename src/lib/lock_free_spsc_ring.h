/*
 * lock_free_spsc_ring.c
 *
 *  Created on: 31 mars 2016
 *      Author: nhnghia
 */

#ifndef SRC_LOCK_FREE_SPSC_RING_H_
#define SRC_LOCK_FREE_SPSC_RING_H_

#include <stdint.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdatomic.h>
#include <time.h>
#include <semaphore.h>
#include "mmt_lib.h"

#define RING_EMPTY  -1
#define RING_FULL   -2
#define RING_SUCCESS 0

typedef struct lock_free_spsc_ring_struct
{
    volatile uint32_t _head __attribute__ ((aligned(16)));
    volatile uint32_t _tail __attribute__ ((aligned(16)));

    uint32_t _cached_head __attribute__ ((aligned(16)));
    uint32_t _cached_tail __attribute__ ((aligned(16)));

    uint32_t _size;

    void **_data;

    //pthread_mutex_t mutex_wait_pushing, mutex_wait_poping;
    //pthread_cond_t cond_wait_pushing, cond_wait_poping;
    sem_t sem_wait_pushing, sem_wait_poping;

}lock_free_spsc_ring_t;

/**
 * Create a circular buffer. This is thread-safe only in when there is one
 * producer and one consumer that are 2 different threads.
 * The producer accesses only the functions: #ring_push and #ring_wait_for_poping,
 * meanwhile the consumer accesses only the functions: #ring_pop and #ring_wait_for_pushing.
 * - Input:
 * 	+ size: buffer size
 * - Return:
 * 	- buffer
 */
lock_free_spsc_ring_t* ring_init( uint32_t size );

/**
 * Push a pointer to the buffer.
 * This function can be called only by producer.
 * - Input:
 * 	+ q: the buffer to be pushed
 * 	+ val:
 * - Return:
 * 	+ RING_SUCESS if #val was successfully pushed into buffer
 * 	+ RING_FULL if the buffer is full, thus the #val is not inserted
 * 	If one stills want to insert #val, thus need to call #ring_wait_for_poping then
 * 	try to push again by calling #ring_push
 */
static inline int  ring_push( lock_free_spsc_ring_t *q, void* val  ){
	uint32_t h;
	h = q->_head;

	//I always let 2 available elements between head -- tail
	//1 empty element for future inserting, 1 element being reading by the consumer
	if( ( h + 3 ) % ( q->_size ) == q->_cached_tail ){
		q->_cached_tail = atomic_load_explicit( &q->_tail, memory_order_acquire );

	/* tail can only increase since the last time we read it, which means we can only get more space to push into.
		 If we still have space left from the last time we read, we don't have to read again. */
		if( ( h + 3 ) % ( q->_size ) == q->_cached_tail )
			return RING_FULL;
	}
	//not full

	q->_data[ h ] = val;

	atomic_store_explicit( &q->_head, (h +1) % q->_size, memory_order_release );

//	sem_post( &q->sem_wait_pushing );

	return RING_SUCCESS;
}


/**
 * Pop an element of buffer.
 * This function can be called only by consumer.
 * - Input:
 * 	+ q: ring to pop
 * - Output:
 * 	+ val: point to the result element if success
 * - Return:
 * 	+ RING_SUCCESS if everything is OK
 * 	+ RING_EMPTY if the buffer is empty
 */

static inline int  ring_pop ( lock_free_spsc_ring_t *q, void **val ){
	uint32_t  t;
	t = q->_tail;

	if( q->_cached_head == t )
		q->_cached_head = atomic_load_explicit ( &q->_head, memory_order_acquire );

	 /* head can only increase since the last time we read it, which means we can only get more items to pop from.
		 If we still have items left from the last time we read, we don't have to read again. */
	if( q->_cached_head == t )
		return RING_EMPTY;
	else{
		//not empty
		*val = q->_data[ t ];

		atomic_store_explicit( &q->_tail, (t+1) % q->_size, memory_order_release );

		return RING_SUCCESS;
	}
}

/**
 * Pop all elements of buffer.
 * This function can be called only by consumer
 * - Input:
 * 	+q: ring to pop
 * - Ouput:
 * 	+ val_arr: array of pointers points to data
 * - Return:
 * 	- number of elements popped successfully
 * - Note:
 * 	In the case this function can pop at least one element, it will create a
 * 	new array, pointed by #val_arr, to contain the elements.
 * 	Therefore one need to free this array by calling mmt_mem_free( val_arr ) after
 * 	using the array.
 */
static inline size_t ring_pop_burst( lock_free_spsc_ring_t *q, void ***val_arr ){
	int size, j;
	uint32_t t = q->_tail;

	if( q->_cached_head == t ){
		q->_cached_head = atomic_load_explicit ( &q->_head, memory_order_acquire );

	 /* head can only increase since the last time we read it, which means we can only get more items to pop from.
		 If we still have items left from the last time we read, we don't have to read again. */
		if( q->_cached_head == t ) return 0;
	}

	//not empty
	//this condition ensures that we get a continues memory segment
	//=> to use memcpy
	if( q->_cached_head > t ){
		size = q->_cached_head - t;
	}else{
		size = q->_size - t;
	}

	*val_arr = mmt_mem_dup( &(q->_data[t]), size * sizeof( void *) );

	atomic_store_explicit( &q->_tail, (t + size) % q->_size, memory_order_release );

	return size;
}

/**
 * Free a buffer.
 * This function frees resource using by the buffer and also the pointer #q
 */
void ring_free( lock_free_spsc_ring_t *q );

/**
 *
 */
static inline void ring_wait_for_pushing( lock_free_spsc_ring_t *q ){
	nanosleep( (const struct timespec[]){{0, 10000L}}, NULL );
//	if( unlikely( sem_trywait( &q->sem_wait_pushing) == 0 ))
//		return; //already lock
//	else{
//		sem_wait( &q->sem_wait_pushing );
//	}
}


static inline void ring_wait_for_poping( lock_free_spsc_ring_t *q ){
	nanosleep( (const struct timespec[]){{0, 100L}}, NULL );
}

#endif /* SRC_QUEUE_LOCK_FREE_SPSC_RING_H_ */
