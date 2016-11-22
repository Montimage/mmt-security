/*
 * lock_free_spsc_ring.c
 *
 *  Created on: 31 mars 2016
 *      Author: nhnghia
 */

#ifndef SRC_LOCK_FREE_SPSC_RING_H_
#define SRC_LOCK_FREE_SPSC_RING_H_

#include <stdint.h>

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
int  ring_push( lock_free_spsc_ring_t *q, void* val  );

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
int  ring_pop ( lock_free_spsc_ring_t *q, void **val );

/**
 * Free a buffer.
 * This function frees resource using by the buffer and also the pointer #q
 */
void ring_free( lock_free_spsc_ring_t *q );

/**
 *
 */
void ring_wait_for_pushing( lock_free_spsc_ring_t *q );
void ring_wait_for_poping( lock_free_spsc_ring_t *q );

#endif /* SRC_QUEUE_LOCK_FREE_SPSC_RING_H_ */
