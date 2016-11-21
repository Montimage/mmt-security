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

lock_free_spsc_ring_t* ring_init( uint32_t size );
int  ring_push( lock_free_spsc_ring_t *q, void* val  );
int  ring_pop ( lock_free_spsc_ring_t *q, void **val );
void ring_free( lock_free_spsc_ring_t *q );

void ring_wait_for_pushing( lock_free_spsc_ring_t *q );
void ring_wait_for_poping( lock_free_spsc_ring_t *q );

#endif /* SRC_QUEUE_LOCK_FREE_SPSC_RING_H_ */
