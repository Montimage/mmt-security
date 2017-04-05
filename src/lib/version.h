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


static inline uint32_t mmt_sec_get_version_number(){
	const char *str = VERSION;
	uint32_t val = 0;
	int percent = 100*100*100;

	do{
		val += percent * atoi( str );

		//jump over number
		while( 1 ){
			if( *str > '9' || *str < '0' )
				break;
			str ++;
		}
		//jump over .
		str ++;

		percent /= 100;

	}while( *str != '\0' && percent != 1 );

	return val;
}

#endif /* SRC_LIB_VERSION_H_ */
