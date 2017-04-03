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
	#define VERSION "1.0.2"
#endif

#define __NOW__ __DATE__ " " __TIME__

#ifdef GIT_VERSION
	//GIT_VERSION is given by Makefile
	#define MMT_SEC_VERSION VERSION " (" GIT_VERSION " - " __NOW__ ")"
#else
	#define MMT_SEC_VERSION VERSION " (" __NOW__ ")"
	#define GIT_VERSION ""
#endif


static inline long mmt_sec_get_version_number(){
	const char *string = VERSION;
	long v = 0;
	return v;
}

#endif /* SRC_LIB_VERSION_H_ */
