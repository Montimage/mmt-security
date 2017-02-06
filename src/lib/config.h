/*
 * mmt_sec_config.h
 *
 *  Created on: 23 nov. 2016
 *      Author: la_vinh
 */

#ifndef MMT_SEC_CONFIG_H_
#define MMT_SEC_CONFIG_H_
#include <stdio.h>
#include <inttypes.h>

typedef struct config_struct {

	/**
	 * Memory pool
	 * When mmt-sec frees a block of memory, it will not call #free immediately.
	 * It will be stored by a memory pool (if the pool is not full).
	 * When mmt-sec requires a block of memory, it will call #malloc only if #mem_pool
	 * has no block having the same size.
	 */
	struct{
		/**
		 * maximum bytes a thread may be reserved by using mmt_mem_pool
		 */
		uint32_t max_bytes;
		/**
		 * maximum elements of a pool of a mem_pool
		 * A mem_pool contains several pools. Each pool stores several blocks of memory
		 * having the same size.
		 * This parameter set the maximum elements of a pool.
		 */
		uint32_t max_elements_per_pool;
	}mem_pool;

	struct{
		/**
		 * number of fsm instances of one rule
		 */
		uint32_t max_instances;

		/**
		 * for multi-thread
		 */
		struct{
			uint32_t ring_size;
		}smp;
	}security;

	struct{
		/**
		 * Number of consecutive alerts of one rule can be ignored its description.
		 * The first alert of a rule always contain description of its rule.
		 * However, to avoid a huge output, a number of consecutive alerts of that rule
		 * can be excluded the description.
		 *
		 * - set = 0 to include description to any alerts
		 */
		uint16_t inorge_description;
	}output;

	struct{
		/**
		 * maximum size, in bytes, of a report received from mmt-probe
		 */
		uint32_t max_report_size;
	}input;
}config_t;


const config_t * get_config();

#endif /* MMT_SEC_CONFIG_H_ */
