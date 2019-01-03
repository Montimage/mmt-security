/*
 * hash_table.c
 *
 * Created on: Jun 7, 2018
 *         by: Huu Nghia Nguyen
 *
 */


#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

#include "mmt_ring.h"
#include "cuckoo_hash_table.h"

/**
 * Aligns input parameter to the next power of 2
 */
static inline uint32_t _align32_power_of_2(uint32_t x){
	x--;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;

	return x + 1;
}

/**
 * Returns true if n is a power of 2
 */
static inline bool _is_power_of_2( uint32_t n ) {
	return n && !(n & (n - 1));
}

#define RTE_PTR_ADD(ptr, x) ((void*)((uintptr_t)(ptr) + (x)))

#ifdef DEBUG
	#define RETURN_IF_TRUE(cond, retval)
		while (cond) return retval
#else
	#define RETURN_IF_TRUE(cond, retval)
#endif

#define zmalloc( x ) calloc( 1, x )

/** Number of items per bucket. */
#define BUCKET_ENTRIES_SIZE		8
#define NULL_SIGNATURE			0
#define EMPTY_SLOT			    0
#define KEY_ALIGNMENT			16
#define MAX_PUSHES             100
#define MAKE_ROOM_DEPTH          8

/* Structure that stores key-value pair */
typedef struct {
	void *pkey;
	/* data value */
	void *pdata;
} entry_key_t __attribute__((aligned(KEY_ALIGNMENT)));



/* Bucket structure */
struct hash_bucket {
	uint32_t sig_current[BUCKET_ENTRIES_SIZE];

	uint32_t key_idx[BUCKET_ENTRIES_SIZE];

	uint32_t sig_alt[BUCKET_ENTRIES_SIZE];

	uint8_t flag[BUCKET_ENTRIES_SIZE];
};

/* A hash table structure. */
struct cuckoo_hash_table{
	uint32_t nb_entries;            /**< Total table entries. */
	uint32_t num_buckets;           /**< Number of buckets in table. */

	mmt_ring_t *free_slots;
	/**< Ring that stores all indexes of the free slots in the key table */

	/* Fields used in lookup */

	/**< Length of hash key. */
	key_cmp_function_t   key_cmp_fn;
	key_hash_function_t  key_hash_fn;

	/**< Indicates which signature compare function to use. */
	uint32_t bucket_bitmask;
	/**< Bitmask for getting bucket index from hash signature. */
	uint32_t key_entry_size;         /**< Size of each key entry. */

	void *key_store;                /**< Table storing all keys and data */
	struct hash_bucket *buckets;
	/**< Table with buckets storing all the	hash values and key indexes
	 * to the key table.
	 */
};


/**
 * Calculate a hash number of key
 */
static inline uint32_t _primary_hash( const cuckoo_hash_t *h, const void *key ){
	return h->key_hash_fn( key );
}


/**
 *  Calc the secondary hash value from the primary hash value of a given key
 */
static inline uint32_t _secondary_hash( uint32_t primary_hash) {
	const unsigned all_bits_shift = 12;
	const unsigned alt_bits_xor = 0x5bd1e995;

	uint32_t tag = primary_hash >> all_bits_shift;

	return primary_hash ^ ((tag + 1) * alt_bits_xor);
}


cuckoo_hash_t *cuckoo_hash_create( uint32_t total_entries, key_hash_function_t key_hash_fn, key_cmp_function_t key_cmp_fn ){
	cuckoo_hash_t *h = NULL;
	mmt_ring_t *r = NULL;
	void *k = NULL;
	void *buckets = NULL;
	unsigned num_key_slots;
	unsigned i;

	/* Check for valid parameters */
	if ((total_entries > CUCKOO_HASH_TABLE_ENTRIES_MAX)
			|| (total_entries < BUCKET_ENTRIES_SIZE)
			|| !_is_power_of_2(BUCKET_ENTRIES_SIZE)
			|| (key_hash_fn == NULL)
			|| (key_cmp_fn == NULL)
	) {
		fprintf(stderr, "cuckoo_hash_create has invalid parameters\n");
		return NULL;
	}

	num_key_slots = total_entries + 1;

	r = mmt_ring_create(_align32_power_of_2(num_key_slots - 1));
	if (r == NULL) {
		fprintf(stderr, "memory allocation failed\n");
		goto err;
	}

	h = (cuckoo_hash_t *) zmalloc(sizeof(cuckoo_hash_t));
	if (h == NULL) {
		fprintf(stderr, "memory allocation failed\n");
		goto err;
	}

	const uint32_t num_buckets = _align32_power_of_2(total_entries) / BUCKET_ENTRIES_SIZE;

	buckets = zmalloc(num_buckets * sizeof(struct hash_bucket));
	if (buckets == NULL) {
		fprintf(stderr, "memory allocation failed\n");
		goto err;
	}

	const uint32_t key_entry_size = sizeof(entry_key_t);
	const uint64_t key_tbl_size   = (uint64_t) key_entry_size * num_key_slots;

	k = malloc( key_tbl_size );

	if (k == NULL) {
		printf("memory allocation failed\n");
		goto err;
	}

	/* Setup hash context */
	h->nb_entries = total_entries;
	h->key_entry_size = key_entry_size;

	h->num_buckets = num_buckets;
	h->bucket_bitmask = h->num_buckets - 1;
	h->buckets = buckets;
	h->key_store = k;
	h->free_slots = r;

	h->key_cmp_fn  = key_cmp_fn;
	h->key_hash_fn = key_hash_fn;

	/* Populate free slots ring. Entry zero is reserved for key misses. */
	for (i = 1; i < r->size; i++)
		mmt_ring_put(r, (void *) ((uintptr_t) i));

	return h;

	err:
	mmt_ring_free(r);
	free(h);
	free(buckets);
	free(k);

	return NULL;
}

void cuckoo_hash_free(cuckoo_hash_t *h) {
	if (h == NULL)
		return;

	mmt_ring_free(h->free_slots);
	free(h->key_store);
	free(h->buckets);
	free(h);
}

void cuckoo_hash_reset(cuckoo_hash_t *h) {
	void *ptr;
	unsigned i;

	if (h == NULL)
		return;

	memset(h->buckets,   0, h->num_buckets    * sizeof(struct hash_bucket));
	memset(h->key_store, 0, h->key_entry_size * (h->nb_entries + 1));

	/* clear the free ring */
	mmt_ring_clear(h->free_slots);

	/* Repopulate the free slots ring. Entry zero is reserved for key misses */
	for (i = 1; i < h->nb_entries + 1; i++)
		mmt_ring_put(h->free_slots, (void *) ((uintptr_t) i));
}

/* Search for an entry that can be pushed to its alternative location */
static inline int _make_space_bucket(const cuckoo_hash_t *h,
		struct hash_bucket *bkt, const int depth) {
	static unsigned int nr_pushes;
	unsigned i, j;
	int ret;
	uint32_t next_bucket_idx;
	struct hash_bucket *next_bkt[BUCKET_ENTRIES_SIZE];

	if (depth == 0)
		return -ENOSPC;

	/*
	 * Push existing item (search for bucket with space in
	 * alternative locations) to its alternative location
	 */
	for (i = 0; i < BUCKET_ENTRIES_SIZE; i++) {
		/* Search for space in alternative locations */
		next_bucket_idx = bkt->sig_alt[i] & h->bucket_bitmask;
		next_bkt[i] = &h->buckets[next_bucket_idx];
		for (j = 0; j < BUCKET_ENTRIES_SIZE; j++) {
			if (next_bkt[i]->key_idx[j] == EMPTY_SLOT)
				break;
		}

		if (j != BUCKET_ENTRIES_SIZE)
			break;
	}

	/* Alternative location has spare room (end of recursive function) */
	if (i != BUCKET_ENTRIES_SIZE) {
		next_bkt[i]->sig_alt[j] = bkt->sig_current[i];
		next_bkt[i]->sig_current[j] = bkt->sig_alt[i];
		next_bkt[i]->key_idx[j] = bkt->key_idx[i];
		return i;
	}

	/* Pick entry that has not been pushed yet */
	for (i = 0; i < BUCKET_ENTRIES_SIZE; i++)
		if (bkt->flag[i] == 0)
			break;

	/* All entries have been pushed, so entry cannot be added */
	if (i == BUCKET_ENTRIES_SIZE || nr_pushes > MAX_PUSHES)
		return -ENOSPC;

	/* Set flag to indicate that this entry is going to be pushed */
	bkt->flag[i] = 1;

	nr_pushes++;
	/* Need room in alternative bucket to insert the pushed entry */
	ret = _make_space_bucket(h, next_bkt[i], depth - 1);
	/*
	 * After recursive function.
	 * Clear flags and insert the pushed entry
	 * in its alternative location if successful,
	 * or return error
	 */
	bkt->flag[i] = 0;
	nr_pushes = 0;
	if (ret >= 0) {
		next_bkt[i]->sig_alt[ret] = bkt->sig_current[i];
		next_bkt[i]->sig_current[ret] = bkt->sig_alt[i];
		next_bkt[i]->key_idx[ret] = bkt->key_idx[i];
		return i;
	} else
		return ret;
}

int cuckoo_hash_add(const cuckoo_hash_t *h, void *key, void *data) {

	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);

	uint32_t sig = _primary_hash(h, key);
	uint32_t alt_hash;
	uint32_t prim_bucket_idx, sec_bucket_idx;
	unsigned i;
	struct hash_bucket *prim_bkt, *sec_bkt;
	entry_key_t *new_k, *k, *keys = h->key_store;
	void *slot_id = NULL;
	uint32_t new_idx;
	int ret;
	unsigned n_slots;
	unsigned lcore_id;

	prim_bucket_idx = sig & h->bucket_bitmask;
	prim_bkt = &h->buckets[prim_bucket_idx];

	alt_hash = _secondary_hash(sig);
	sec_bucket_idx = alt_hash & h->bucket_bitmask;
	sec_bkt = &h->buckets[sec_bucket_idx];

	if ( ! mmt_ring_dequeuet(h->free_slots, &slot_id) )
		return -ENOSPC; //there is no space in the hash for this key.

	new_k = RTE_PTR_ADD(keys, (uintptr_t )slot_id * h->key_entry_size);

	new_idx = (uint32_t) ((uintptr_t) slot_id);

	/* Check if key is already inserted in primary location */
	for (i = 0; i < BUCKET_ENTRIES_SIZE; i++) {
		if (prim_bkt->sig_current[i] == sig
				&& prim_bkt->sig_alt[i] == alt_hash) {
			k = (entry_key_t *) ((char *) keys
					+ prim_bkt->key_idx[i] * h->key_entry_size);
			if (h->key_cmp_fn( key, k->pkey ) == 0) {
				/*
				 * enqueue back an index in the cache/ring,
				 * as slot has not being used and it can be used in the
				 * next addition attempt.
				 */

				/* Enqueue index of free slot back in the ring. */
				mmt_ring_enqueue(h->free_slots, slot_id);

				/* Update data */
				k->pdata = data;
				return 0;
			}
		}
	}

	/* Check if key is already inserted in secondary location */
	for (i = 0; i < BUCKET_ENTRIES_SIZE; i++) {
		if (sec_bkt->sig_alt[i] == sig && sec_bkt->sig_current[i] == alt_hash) {

			k = (entry_key_t *) ((char *) keys
					+ sec_bkt->key_idx[i] * h->key_entry_size);

			if (h->key_cmp_fn(key, k->pkey) == 0) {

				/* Enqueue index of free slot back in the ring. */
				mmt_ring_put(h->free_slots, slot_id);

				/* Update data */
				k->pdata = data;
				return 0;
			}
		}
	}

	/* store key-data reference */
	new_k->pkey  = key;
	new_k->pdata = data;

	for (i = 0; i < BUCKET_ENTRIES_SIZE; i++) {
		/* Check if slot is available */
		if (prim_bkt->key_idx[i] == EMPTY_SLOT) {
			prim_bkt->sig_current[i] = sig;
			prim_bkt->sig_alt[i] = alt_hash;
			prim_bkt->key_idx[i] = new_idx;
			break;
		}
	}

	if (i != BUCKET_ENTRIES_SIZE)
		return 0;

	/* Primary bucket full, need to make space for new entry
	 * After recursive function.
	 * Insert the new entry in the position of the pushed entry
	 * if successful or return error and
	 * store the new slot back in the ring
	 */
	ret = _make_space_bucket(h, prim_bkt, MAKE_ROOM_DEPTH);
	if (ret >= 0) {
		prim_bkt->sig_current[ret] = sig;
		prim_bkt->sig_alt[ret] = alt_hash;
		prim_bkt->key_idx[ret] = new_idx;
		return new_idx - 1;
	}
	/* Error in addition, store new slot back in the ring and return error */
	mmt_ring_put(h->free_slots, (void *) ((uintptr_t) new_idx));

	if (ret >= 0)
		return 0;
	else
		return ret;
}

int cuckoo_hash_lookup(const cuckoo_hash_t *h, const void *key, void **data) {
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);

	uint32_t sig = _primary_hash(h, key);
	uint32_t bucket_idx;
	uint32_t alt_hash;
	unsigned i;
	struct hash_bucket *bkt;
	entry_key_t *k, *keys = h->key_store;

	bucket_idx = sig & h->bucket_bitmask;
	bkt = &h->buckets[bucket_idx];

	/* Check if key is in primary location */
	for (i = 0; i < BUCKET_ENTRIES_SIZE; i++) {
		if (bkt->sig_current[i] == sig && bkt->key_idx[i] != EMPTY_SLOT) {
			k = (entry_key_t *) ((char *) keys
					+ bkt->key_idx[i] * h->key_entry_size);
			if ( h->key_cmp_fn(key, k->pkey) == 0) {
				if (data != NULL)
					*data = k->pdata;
				/*
				 * Return index where key is stored,
				 * substracting the first dummy index
				 */
				return bkt->key_idx[i] - 1;
			}
		}
	}

	/* Calculate secondary hash */
	alt_hash = _secondary_hash(sig);
	bucket_idx = alt_hash & h->bucket_bitmask;
	bkt = &h->buckets[bucket_idx];

	/* Check if key is in secondary location */
	for (i = 0; i < BUCKET_ENTRIES_SIZE; i++) {
		if (bkt->sig_current[i] == alt_hash && bkt->sig_alt[i] == sig) {
			k = (entry_key_t *) ((char *) keys
					+ bkt->key_idx[i] * h->key_entry_size);
			if (h->key_cmp_fn(key, k->pkey) == 0) {
				if (data != NULL)
					*data = k->pdata;
				/*
				 * Return index where key is stored,
				 * substracting the first dummy index
				 */
				return bkt->key_idx[i] - 1;
			}
		}
	}

	return -ENOENT;
}

static inline void _remove_entry(const cuckoo_hash_t *h,
		struct hash_bucket *bkt, unsigned i) {

	bkt->sig_current[i] = NULL_SIGNATURE;
	bkt->sig_alt[i] = NULL_SIGNATURE;

	//stock the free block
	mmt_ring_enqueue(h->free_slots, (void *) ((uintptr_t) bkt->key_idx[i]));
}

int32_t cuckoo_hash_del(const cuckoo_hash_t *h, const void *key) {
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);

	uint32_t sig = _primary_hash(h, key);
	uint32_t bucket_idx;
	uint32_t alt_hash;
	unsigned i;
	struct hash_bucket *bkt;
	entry_key_t *k, *keys = h->key_store;
	int32_t ret;

	bucket_idx = sig & h->bucket_bitmask;
	bkt = &h->buckets[bucket_idx];

	/* Check if key is in primary location */
	for (i = 0; i < BUCKET_ENTRIES_SIZE; i++) {
		if (bkt->sig_current[i] == sig && bkt->key_idx[i] != EMPTY_SLOT) {
			k = (entry_key_t *) ((char *) keys
					+ bkt->key_idx[i] * h->key_entry_size);
			if ( h->key_cmp_fn(key, k->pkey) == 0) {
				_remove_entry(h, bkt, i);

				/*
				 * Return index where key is stored,
				 * substracting the first dummy index
				 */
				ret = bkt->key_idx[i] - 1;
				bkt->key_idx[i] = EMPTY_SLOT;
				return ret;
			}
		}
	}

	/* Calculate secondary hash */
	alt_hash = _secondary_hash(sig);
	bucket_idx = alt_hash & h->bucket_bitmask;
	bkt = &h->buckets[bucket_idx];

	/* Check if key is in secondary location */
	for (i = 0; i < BUCKET_ENTRIES_SIZE; i++) {
		if (bkt->sig_current[i] == alt_hash && bkt->key_idx[i] != EMPTY_SLOT) {
			k = (entry_key_t *) ((char *) keys
					+ bkt->key_idx[i] * h->key_entry_size);
			if (h->key_cmp_fn(key, k->pkey) == 0) {
				_remove_entry(h, bkt, i);

				/*
				 * Return index where key is stored,
				 * substracting the first dummy index
				 */
				ret = bkt->key_idx[i] - 1;
				bkt->key_idx[i] = EMPTY_SLOT;
				return ret;
			}
		}
	}

	return -ENOENT;
}

int32_t cuckoo_hash_iterate(const cuckoo_hash_t *h,
		void **key,
		void **data, uint32_t *next) {

	uint32_t bucket_idx, idx, position;
	entry_key_t *next_key;

	RETURN_IF_TRUE(((h == NULL) || (next == NULL)), -EINVAL);

	const uint32_t total_entries = h->num_buckets * BUCKET_ENTRIES_SIZE;
	/* Out of bounds */
	if (*next >= total_entries)
		return -ENOENT;

	/* Calculate bucket and index of current iterator */
	bucket_idx = *next / BUCKET_ENTRIES_SIZE;
	idx = *next % BUCKET_ENTRIES_SIZE;

	/* If current position is empty, go to the next one */
	while (h->buckets[bucket_idx].key_idx[idx] == EMPTY_SLOT) {
		(*next)++;
		/* End of table */
		if (*next == total_entries)
			return -ENOENT;
		bucket_idx = *next / BUCKET_ENTRIES_SIZE;
		idx = *next % BUCKET_ENTRIES_SIZE;
	}

	/* Get position of entry in key table */
	position = h->buckets[bucket_idx].key_idx[idx];
	next_key = (entry_key_t *) ((char *) h->key_store
			+ position * h->key_entry_size);
	/* Return key and data */
	if( key != NULL )
		*key  = next_key->pkey;
	if( data != NULL )
		*data = next_key->pdata;

	/* Increment iterator */
	(*next)++;

	return position - 1;
}
