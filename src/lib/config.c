/*
 * mmt_sec_config.c
 *
 *  Created on: 23 nov. 2016
 *      Author: la_vinh
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "config.h"

static config_t config = {
		.mem_pool = {
				.max_bytes    = 2*1000*1000*1000, //2GB per thread
				.max_elements_per_pool = 200
		},
		.security = {
			.max_instances = 1000,
			.smp = {
				.ring_size = 1000
			}
		},
		.output = {
				.inorge_description = 20
		},
		.input = {
				.max_report_size = 1000
		}
};

const config_t * get_config(){
	return &config;
}
