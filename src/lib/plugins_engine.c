/*
 * plugins_engine.c
 *
 *  Created on: Oct 10, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */
#include <dirent.h>
#include <dlfcn.h>
#include <stdlib.h>

#include "plugins_engine.h"
#include "base.h"
#include "mmt_alloc.h"
#include "mmt_log.h"
#include "data_struct.h"

#define MAX_PLUGIN_COUNT 1000

static int load_filter( const struct dirent *entry ){
	char *ext = strrchr( entry->d_name, '.' );
	return( ext && !strcmp( ext, ".so" ));
}

size_t load_plugins( const rule_info_t **plugins_arr ){
	size_t size, i, index;
	char path[ 256 ];
	struct dirent **entries, *entry;
	int plugins_path=0;
	mmt_map_t *plugins_set = NULL;
	uint32_t *key;
	const rule_info_t *plugins[ MAX_PLUGIN_COUNT ];
	int n;

	n = scandir( PLUGINS_REPOSITORY, &entries, load_filter, alphasort );
	if( n < 0 ) {
		/* can't read PLUGINS_REPOSITORY -> just ignore and return success
		 * (the directory may not exist or may be inaccessible, that's ok)
		 * note: no entries were allocated at this point, no need for free().
		 */
		plugins_path=1;
		n = scandir( PLUGINS_REPOSITORY_OPT, &entries, load_filter, alphasort );
		if (n<0)	return 0;
	}

	plugins_set = mmt_map_init( compare_uint32_t );
	index = 0;
	for( i = 0 ; i < n ; ++i ) {
		entry = entries[i];
		(void)snprintf( path, 256, "%s/%s",plugins_path==0?PLUGINS_REPOSITORY:PLUGINS_REPOSITORY_OPT,entry->d_name );
		// printf("Loading plugins from: %s \n",path);
		size = load_plugin( plugins_arr, path );
		//add to plugins_set
		for( i=0; i<size; i++ ){
			key = mmt_malloc( sizeof( uint32_t));
			*key = plugins_arr[i]->id;
			//no key exist before?
			if( mmt_map_set_data( plugins_set, key, NULL, NO ) == NULL){
				plugins[ index ++ ] = plugins_arr[ i ];
			}else{
				mmt_debug( "Duplicate rules'id %d", *key);
				mmt_free( key );
			}
		}
		free( entry );
		*plugins_arr = mmt_mem_dup( plugins, index * sizeof( rule_info_t*) );
	}
	free( entries );



	return size;
}

size_t load_plugin( const rule_info_t **plugins_arr, const char *plugin_path_name ){
	void *lib = dlopen ( plugin_path_name, RTLD_LAZY );
	mmt_assert( lib != NULL, "Cannot open library: %s.\n%s", plugin_path_name, dlerror() );

	size_t ( *fn ) ( const rule_info_t ** ) = dlsym ( lib, "mmt_sec_get_plugin_info" );
	mmt_assert( fn != NULL, "Cannot find function: mmt_sec_get_plugin_info");

	return fn( plugins_arr );
}

void close_plugins() {

}
