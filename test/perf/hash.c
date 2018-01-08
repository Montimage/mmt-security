/*
 * hash.c
 *
 *  Created on: Oct 9, 2017
 *      Author: nhnghia
 */

/**
 * Result:
 * rm test/perf/hash.o
 * found 5000, time 0.114808
 * found 5000, time 0.009536
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include "../../src/lib/mmt_lib.h"

#define LEN 50
#define LOOP 20000000


struct entry_struct{
	uint32_t low;
	uint32_t high;
} entry[ LEN ];

mmt_hash_t *hash_table = NULL;

uint64_t keys[ LOOP ];

static inline int naif_lookup( const struct entry_struct *e ){
	int i;
	for( i=0; i<LEN; i++ )
		if( entry[i].high == e->high && entry[i].low == e->low )
			return i;

	return -1;
}

void swap( uint32_t *x, uint32_t *y ){
	uint32_t tmp = *x;
	*x = *y;
	*y = tmp;
}

void sort(){
	size_t i,j;
	for( i=0; i<LEN; i++ )
		for( j=i+1; j<LEN; j++ ){
			if( *((uint64_t *) &entry[i]) > *((uint64_t *) &entry[j]) ){
				swap( &entry[i].low,  &entry[j].low );
				swap( &entry[i].high, &entry[j].high );
			}
		}
}

void print(){
	size_t i;
	for( i=0; i<LEN; i++ )
		printf("%10d\n", *((uint64_t *) & entry[i]) );
}
//
//int sort_lookup( const struct entry_struct *e ){
//	uint64_t key = e->low + e->high;
//	int binarySearch(int *array, int number_of_elements, int key) {
//		int low = 0, high = number_of_elements-1, mid;
//		while(low <= high) {
//			mid = (low + high)/2;
//
//	#ifdef DO_PREFETCH
//			// low path
//			__builtin_prefetch (&array[(mid + 1 + high)/2], 0, 1);
//			// high path
//			__builtin_prefetch (&array[(low + mid - 1)/2], 0, 1);
//	#endif
//
//			if(array[mid] < key)
//				low = mid + 1;
//			else if(array[mid] == key)
//				return mid;
//			else if(array[mid] > key)
//				high = mid-1;
//		}
//		return -1;
//	}

size_t node_count( mmt_hash_t *table ){
	size_t i;
	size_t count = CHILDREN_COUNT;
	if( table == NULL )
		return 0;

	for( i=0; i<CHILDREN_COUNT; i++ )
		count += node_count( table->children[i] );
	return count;
}


int main( int argc, char **argv){
	uint64_t i, j, count;

	clock_t time_t;

	//init random
	srand(time(NULL));

	//init entry
	for( i=0; i<LEN; i++ ){
		entry[i].low  = i;
		entry[i].high = rand();
	}

	//init hash table
	hash_table = mmt_hash_create();
	for( i=0; i<LEN; i++ )
		mmt_hash_add(hash_table, &entry[i], 8, (void *) i, NO);

	//init keys
	for( i=0; i<LOOP; i++ )
//		keys[i] = rand();
		keys[i] = *((uint64_t *)  & entry[i % LEN]);


	count = 0;
	time_t = clock();
	for( i=0; i<LOOP; i++ ){
		j = naif_lookup( (struct entry_struct *) &keys[i] );
		if( i%LEN == j )
			count ++;
	}

	printf("found %d, node %10ld, size %10zu, time %.6f\n", count,
				LEN, sizeof( entry ),
				(float)(clock() - time_t) / CLOCKS_PER_SEC);

	count = 0;
	time_t = clock();
	for( i=0; i<LOOP; i++ ){
		j = (uint64_t )mmt_hash_search(hash_table, (struct entry_struct *) &keys[i], 8 );
		if( i%LEN == j )
			count ++;
	}

	size_t size = 0;// node_count( hash_table);
	printf("found %ld, node %10zu, size %10zu, time %.6f\n", count,
			size,  size * sizeof( mmt_hash_t ),
			(double)(clock() - time_t) / CLOCKS_PER_SEC);

	/*
	print();
	sort();
	printf("-------\n");
	print();
	*/
	return EXIT_SUCCESS;
}

