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
#include "mmt_lib.h"
#include "version.h"

//TODO: this limit 100K rules
#define MAX_PLUGIN_COUNT 100000

static void *dl_libs[MAX_PLUGIN_COUNT];
static uint32_t dl_libs_index = 0;

static int load_filter( const struct dirent *entry ){
	char *ext = strrchr( entry->d_name, '.' );
	return( ext && !strcmp( ext, ".so" ));
}

//size_t _load_mmt_sec_rules( const rule_info_t ***ret_array ){
//	const rule_info_t *tmp_array, **array;
//	size_t size = 0, i;
////
////	size = mmt_sec_get_plugin_info( &tmp_array );
////	array = mmt_mem_alloc( size * sizeof( void * ));
////	for( i=0; i<size; i++ )
////		array[i] = & tmp_array[i];
////	*ret_array = array;
//
//	return size;
//}

size_t load_mmt_sec_rules( const rule_info_t ***ret_array ){
	size_t size, i, j, index;
	char path[ 256 ];
	struct dirent **entries, *entry;
	int plugins_path=0;
	mmt_map_t *plugins_set = NULL;
	const uint32_t* key;

	rule_info_t const *  plugins_array[ MAX_PLUGIN_COUNT ];
	rule_info_t const ** tmp_array;
	int n;

	unload_mmt_sec_rules();

	n = scandir( MMT_SEC_PLUGINS_REPOSITORY, &entries, load_filter, alphasort );
	if( n < 0 ) {
		/* can't read PLUGINS_REPOSITORY -> just ignore and return success
		 * (the directory may not exist or may be inaccessible, that's ok)
		 * note: no entries were allocated at this point, no need for free().
		 */
		plugins_path=1;
		n = scandir( MMT_SEC_PLUGINS_REPOSITORY_OPT, &entries, load_filter, alphasort );
		if (n<0)	return 0;
	}

	plugins_set = mmt_map_init( compare_uint32_t );
	index = 0;
	for( i = 0 ; i < n ; ++i ) {
		entry = entries[i];
		(void)snprintf( path, 256, "%s/%s",
						plugins_path==0 ? MMT_SEC_PLUGINS_REPOSITORY : MMT_SEC_PLUGINS_REPOSITORY_OPT,
						entry->d_name );

		//load plugin
		size = load_mmt_sec_rule( &tmp_array, path );

		//add rule to array only if it has not been done before to avoid duplicate
		for( j=0; j<size && index < MAX_PLUGIN_COUNT; j++ ){

			key = &(tmp_array[ j ]->id);
			//no key exist before?
			if( mmt_map_set_data( plugins_set, (void *)key, (void *)tmp_array[j], NO ) == NULL){
				plugins_array[ index ++ ] = tmp_array[ j ];
			}else{
				mmt_warn( "Rule %d in file %s uses an existing id", *key, path);
			}
		}

		free( entry );
		mmt_mem_free( tmp_array );
	}
	free( entries );

	//free the map
	mmt_map_free( plugins_set, NO );

	*ret_array = mmt_mem_dup( plugins_array, sizeof( rule_info_t* ) * index);

	return index;
}

size_t load_mmt_sec_rule( rule_info_t const *** plugins_arr, const char *plugin_path_name ){

	void *lib = dlopen( plugin_path_name, RTLD_NOW );

	rule_info_t const* tmp_array;
	rule_info_t const** ret_array;
	size_t size, i, index = 0;
	uint32_t required_plugin = mmt_sec_get_required_plugin_version_number();

	mmt_assert( lib != NULL, "Cannot open library: %s.\n%s", plugin_path_name, dlerror() );

	const rule_version_info_t* ( *mmt_sec_get_rule_version_info ) () = dlsym ( lib, "mmt_sec_get_rule_version_info" );

	mmt_assert( mmt_sec_get_rule_version_info != NULL, "File %s is incorrect!", plugin_path_name );

	if( mmt_sec_get_rule_version_info()->index < required_plugin ){
		mmt_warn( "Ignored rules in file %s as it is not up to date.", plugin_path_name );
		return 0;
	}

	size_t ( *mmt_sec_get_plugin_info ) ( const rule_info_t ** ) = dlsym ( lib, "mmt_sec_get_plugin_info" );
	mmt_assert( mmt_sec_get_plugin_info != NULL, "File %s is incorrect!", plugin_path_name );

	size = mmt_sec_get_plugin_info( &tmp_array );
	ret_array = mmt_mem_alloc( sizeof( rule_info_t *) * size );
	for( i=0; i<size; i++ ){
		if( tmp_array[i].version->index < required_plugin )
			mmt_warn( "Ignored rule %d as it is not up to date.\nRule description: %s",
					tmp_array[i].id,
					tmp_array[i].description );
		else
			ret_array[ index++ ] = & (tmp_array[i] );
	}

	*plugins_arr = ret_array;

	if( dl_libs_index < MAX_PLUGIN_COUNT )
		dl_libs[ dl_libs_index ++ ] = lib;

	return size;
}

void unload_mmt_sec_rules() {
	size_t i, ret = 0;
	for( i=0; i<dl_libs_index; i++ )
		ret |= dlclose( dl_libs[ i ] );

	if( ret != 0 )
		mmt_warn("Cannot close properly mmt-security .so rules");

	dl_libs_index = 0;
}


//call when exiting application
static __attribute__((destructor)) void _destructor () {
	unload_mmt_sec_rules();
}
