/*
 * cuckoo_hash_table.h
 *
 * Created on: Jun 7, 2018
 *         by: Huu Nghia Nguyen
 *
 * A hash table based on cuckoo hash from rte_hash
 */

#ifndef _RTE_HASH_H_
#define _RTE_HASH_H_

#include <stdint.h>
#include <stddef.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum size of hash table that can be created. */
#define CUCKOO_HASH_TABLE_ENTRIES_MAX	(1 << 27) //134 217 728

/**
 * Type of function used to compare 2 keys.
 * Function must return 0 if and only if (key1 == key2)
 */
typedef int (*key_cmp_function_t)(const void *key1, const void *key2);

/**
 * Type of function used to hash a key.
 */
typedef uint32_t (*key_hash_function_t)( const void *key);

/** @internal A hash table structure. */
typedef struct cuckoo_hash_table cuckoo_hash_t;

/**
 * Create a new hash table.
 *
 * @param params
 *   Parameters used to create and initialise the hash table.
 * @return
 *   Pointer to hash table structure that is used in future hash table
 *   operations, or NULL on error
 */
cuckoo_hash_t * cuckoo_hash_create( uint32_t total_entries, key_hash_function_t hash_fn, key_cmp_function_t cmp_fn );

/**
 * De-allocate all memory used by hash table.
 * @param h
 *   Hash table to free
 */
void cuckoo_hash_free(cuckoo_hash_t *h);

/**
 * Reset all hash structure, by zeroing all entries
 * @param h
 *   Hash table to reset
 */
void cuckoo_hash_reset(cuckoo_hash_t *h);

/**
 * Add a key-value pair to an existing hash table.
 * This operation is not multi-thread safe
 * and should only be called from one thread.
 *
 * @param h
 *   Hash table to add the key to.
 * @param key
 *   Key to add to the hash table.
 * @param data
 *   Data to add to the hash table.
 * @return
 *   - 0 if added successfully
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOSPC if there is no space in the hash for this key.
 */
int cuckoo_hash_add(const cuckoo_hash_t *h, void *key, void *data);

/**
 * Remove a key from an existing hash table.
 * This operation is not multi-thread safe
 * and should only be called from one thread.
 *
 * @param h
 *   Hash table to remove the key from.
 * @param key
 *   Key to remove from the hash table.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOENT if the key is not found.
 *   - A positive value that can be used by the caller as an offset into an
 *     array of user data. This value is unique for this key, and is the same
 *     value that was returned when the key was added.
 */
int32_t cuckoo_hash_del(const cuckoo_hash_t *h, const void *key);

/**
 * Find a key-value pair in the hash table.
 * This operation is multi-thread safe.
 *
 * @param h
 *   Hash table to look in.
 * @param key
 *   Key to find.
 * @param data
 *   Output with pointer to data returned from the hash table.
 * @return
 *   0 if successful lookup
 *   - EINVAL if the parameters are invalid.
 *   - ENOENT if the key is not found.
 */
int cuckoo_hash_lookup(const cuckoo_hash_t *h, const void *key, void **data);



/**
 * Iterate through the hash table, returning key-value pairs.
 *
 * @param h
 *   Hash table to iterate
 * @param key
 *   Output containing the key where current iterator
 *   was pointing at
 * @param data
 *   Output containing the data associated with key.
 *   Returns NULL if data was not stored.
 * @param next
 *   Pointer to iterator. Should be 0 to start iterating the hash table.
 *   Iterator is incremented after each call of this function.
 * @return
 *   Position where key was stored, if successful.
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOENT if end of the hash table.
 */
int32_t cuckoo_hash_iterate(const cuckoo_hash_t *h, void **key, void **data, uint32_t *next);
#ifdef __cplusplus
}
#endif

#endif /* _RTE_HASH_H_ */
