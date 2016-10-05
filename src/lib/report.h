/*
 * report.h
 *
 *  Created on: 5 oct. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 *  Report received from MMT-Probe
 */

#ifndef SRC_LIB_REPORT_H_
#define SRC_LIB_REPORT_H_

typedef struct report_element_struct{
	uint32_t proto_id;
	uint32_t attr_id;
	uint32_t hash_id;
	uint32_t data_len;
	void *data;
};

#endif /* SRC_LIB_REPORT_H_ */
