/*
 * version.h
 *
 *  Created on: Nov 3, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_LIB_VERSION_H_
#define SRC_LIB_VERSION_H_

#define VERSION "1.0"

#ifdef GIT_VERSION
	//GIT_VERSION is given by Makefile
	#define MMT_SEC_VERSION VERSION " (" GIT_VERSION ")"
#else
	#define MMT_SEC_VERSION VERSION
#endif

#endif /* SRC_LIB_VERSION_H_ */
