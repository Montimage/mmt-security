/*
 * version.h
 *
 *  Created on: Nov 3, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 *  Define version of mmt-security
 *  One may change #VERSION and #GIT_VERSION from Makefile
 */

#ifndef SRC_LIB_VERSION_H_
#define SRC_LIB_VERSION_H_

#ifndef VERSION
	#define VERSION "1.0"
#endif

#ifdef GIT_VERSION
	//GIT_VERSION is given by Makefile
	#define MMT_SEC_VERSION VERSION " (" GIT_VERSION ")"
#else
	#define MMT_SEC_VERSION VERSION
#endif

#endif /* SRC_LIB_VERSION_H_ */
