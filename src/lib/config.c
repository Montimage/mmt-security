/*
 * mmt_sec_config.c
 *
 *  Created on: 23 nov. 2016
 *      Author: la_vinh
 */
#include <stdlib.h>
#include <string.h>

#include "config.h"

static config_t config = {
		.mem_pool = {
				.max_bytes    = 2*1000*1000*1000, //2GB per thread
				.max_elements_per_pool = 1000
		},
		.security = {
			.max_instances = 100000,
			.rules_mask    = NULL,
			.smp = {
				.ring_size = 5000
			}
		},
		.output = {
				.inorge_description = 20
		},
		.input = {
				.max_message_size = 4000
		}
};

const config_t * get_config(){
	return &config;
}
