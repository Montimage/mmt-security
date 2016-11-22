/*
 * plugin_engine.h
 *
 *  Created on: Oct 10, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 *  One may change #MMT_SEC_PLUGINS_REPOSITORY and #MMT_SEC_PLUGINS_REPOSITORY_OPT from Makefile
 */

#ifndef SRC_LIB_PLUGIN_ENGINE_H_
#define SRC_LIB_PLUGIN_ENGINE_H_

#ifndef MMT_SEC_PLUGINS_REPOSITORY
	#define MMT_SEC_PLUGINS_REPOSITORY "rules"
#endif
#ifndef MMT_SEC_PLUGINS_REPOSITORY_OPT
	#define MMT_SEC_PLUGINS_REPOSITORY_OPT "/opt/mmt/security/rules"
#endif

#include "plugin_header.h"

/**
 * Loads all the plugins.
 * - Return
 * 	+ number of loaded rules
 */
size_t load_mmt_sec_rules( rule_info_t const *** plugins_arr );

/**
 * Loads one plugin.
 * - Return
 * 	+ number of loaded rules
 */
size_t load_mmt_sec_rule( rule_info_t const ***plugins_arr, const char *plugin_path_name );
/**
 * Closes all loaded plugins. This function MUST only be used when the protocols corresponding
 * to the loaded plugins have been retrieved. Normally this function is used when closing the
 * library.
 */
void close_mmt_sec_rules();


#endif /* SRC_LIB_PLUGIN_ENGINE_H_ */
