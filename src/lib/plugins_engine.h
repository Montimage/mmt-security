/*
 * plugin_engine.h
 *
 *  Created on: Oct 10, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_LIB_PLUGIN_ENGINE_H_
#define SRC_LIB_PLUGIN_ENGINE_H_


#define PLUGINS_REPOSITORY "plugins"
#define PLUGINS_REPOSITORY_OPT "/opt/mmt/security/plugins"
#include "plugin_header.h"

/**
 * Loads all the plugins.
 * - Return
 * 	+ number of loaded rules
 */
size_t load_plugins( rule_info_t const *** plugins_arr );

/**
 * Loads one plugin.
 * - Return
 * 	+ number of loaded rules
 */
size_t load_plugin( rule_info_t const ***plugins_arr, const char *plugin_path_name );
/**
 * Closes all loaded plugins. This function MUST only be used when the protocols corresponding
 * to the loaded plugins have been retrieved. Normally this function is used when closing the
 * library.
 */
void close_plugins();


#endif /* SRC_LIB_PLUGIN_ENGINE_H_ */
