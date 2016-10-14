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
size_t load_plugins( const rule_info_t ***ret_array ){
	const rule_info_t *tmp_array, **array;
	size_t size, i;
	size = mmt_sec_get_plugin_info( &tmp_array );
	array = mmt_malloc( size * sizeof( void * ));
	for( i=0; i<size; i++ )
		array[i] = & tmp_array[i];
	*ret_array = array;
	return size;
}
size_t _load_plugins( const rule_info_t ***ret_array ){
	size_t size, i, j, index;
	char path[ 256 ];
	struct dirent **entries, *entry;
	int plugins_path=0;
	mmt_map_t *plugins_set = NULL;
	const uint32_t* key;

	rule_info_t const *  plugins_array[ MAX_PLUGIN_COUNT ];
	rule_info_t const ** tmp_array;
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

		//load plugin
		size = load_plugin( &tmp_array, path );

		//add rule to array only if it has not been done before to avoid duplicate
		for( j=0; j<size && index < MAX_PLUGIN_COUNT; j++ ){

			key = &(tmp_array[ j ]->id);
			//no key exist before?
			if( mmt_map_set_data( plugins_set, (void *)key, (void *)tmp_array[j], NO ) == NULL){
				plugins_array[ index ++ ] = tmp_array[ j ];
			}else{
				mmt_info( "Rule %d in file %s uses an existing id", *key, path);
			}
		}
		free( entry );
		mmt_free( tmp_array );
	}
	free( entries );

	//free the map
	mmt_map_free( plugins_set, NO );

	*ret_array = mmt_mem_dup( plugins_array, sizeof( rule_info_t* ) * index);

	return index;
}

size_t load_plugin( rule_info_t const *** plugins_arr, const char *plugin_path_name ){
	void* lib = dlopen ( plugin_path_name, RTLD_LAZY );
	rule_info_t const* tmp_array;
	rule_info_t const** ret_array;
	size_t size, i;
	mmt_assert( lib != NULL, "Cannot open library: %s.\n%s", plugin_path_name, dlerror() );

	size_t ( *fn ) ( const rule_info_t ** ) = dlsym ( lib, "mmt_sec_get_plugin_info" );
	mmt_assert( fn != NULL, "Cannot find function: mmt_sec_get_plugin_info");

	size = fn( &tmp_array );
	ret_array = mmt_malloc( sizeof( rule_info_t *) * size );
	for( i=0; i<size; i++ )
		ret_array[i] = & (tmp_array[i]);

	*plugins_arr = ret_array;
	return size;
}

void close_plugins() {

}