/*
 * plugin_engine.h
 *
 *  Created on: Oct 10, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_LIB_PLUGIN_ENGINE_H_
#define SRC_LIB_PLUGIN_ENGINE_H_


#define PLUGINS_REPOSITORY "plugins"
#define PLUGINS_REPOSITORY_OPT "/opt/mmt/sec/plugins"
#include "plugin_header.h"

/**
 * Loads all the plugins.
 * @return positive value on success, 0 on failure.
 */
size_t load_plugins( const rule_info_t **plugins_arr );

size_t load_plugin( const rule_info_t **plugins_arr, const char *plugin_path_name );
/**
 * Closes all loaded plugins. This function MUST only be used when the protocols corresponding
 * to the loaded plugins have been retrieved. Normally this function is used when closing the
 * library.
 */
void close_plugins();


#endif /* SRC_LIB_PLUGIN_ENGINE_H_ */
