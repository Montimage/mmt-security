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


typedef struct plugin_struct{
	char *path;                //full path of this plugin
	void *dl_lib;			  //pointer given by dl_open

	const rule_info_t **rules; //array of rules. This array contains only the rules that have different ids with the rules existing
	const rule_info_t **original_rules; //original array of rules

	uint16_t rules_count;    //number of rules in this plugin
	uint16_t original_rules_count;
}plugin_t;

//TODO: this limit 50K files .so and 50K rules
#define MAX_PLUGIN_COUNT 50000
#define MAX_RULES_COUNT  50000

static plugin_t plugins[MAX_PLUGIN_COUNT];
static const rule_info_t *rules[ MAX_RULES_COUNT ];

static uint32_t plugins_count = 0; //number of plugins (number of .so files)
static uint32_t rules_count   = 0; //number of rules inside the plugins



static int _load_filter( const struct dirent *entry ){
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

static inline bool _find_plugin_has_rule_id( uint32_t rule_id, size_t *plugin_index, size_t *rule_index ){
	size_t i, j;
	for( i=0; i<plugins_count; i++ )
		for( j=0; j<plugins[i].rules_count; j++ )
			if( plugins[i].rules[j]->id == rule_id ){
				*plugin_index = i;
				*rule_index   = j;
				return YES;
			}
	return NO;
}

size_t load_mmt_sec_rules( rule_info_t const*const**ret_array ){
	size_t i, j, k;
	char path[ 1001 ];
	struct dirent **entries, *entry;
	const char *plugin_folder;

	rule_info_t const*const* tmp_array;
	int n;

	plugin_folder = MMT_SEC_PLUGINS_REPOSITORY;
	n = scandir( plugin_folder, &entries, _load_filter, alphasort );
	if( n < 0 ) {
		/* can't read PLUGINS_REPOSITORY -> just ignore and return success
		 * (the directory may not exist or may be inaccessible, that's ok)
		 * note: no entries were allocated at this point, no need for free().
		 */
		plugin_folder = MMT_SEC_PLUGINS_REPOSITORY_OPT;
		n = scandir( plugin_folder, &entries, _load_filter, alphasort );
		if (n<0)
			return 0;
	}

	for( i = 0 ; i < n ; ++i ) {
		entry = entries[i];
		(void) snprintf( path, 1000, "%s/%s", plugin_folder, entry->d_name );

		//load plugin
		load_mmt_sec_rule( &tmp_array, path );

		free( entry );
	}
	free( entries );

	//reload rules set
	k = 0;
	//for each plugin
	for( i=0; i<plugins_count; i++ )
		//for each rule inside a plugin
		for( j=0; j<plugins[i].rules_count; j++ )
			rules[ k++ ] = plugins[i].rules[j];

	mmt_assert( k == rules_count, "Must not happen" );

	*ret_array = rules;

	return rules_count;
}


static inline int _find_plugin( const char *lib_path ){
	int i;
	for( i=0; i<plugins_count; i++ )
		//found a path existing in #dl_libs_path
		if( strcmp( lib_path, plugins[i].path ) == 0 )
			return i;

	return plugins_count;
}

/**
 * PUBLIC API
 * @param plugins_arr
 * @param plugin_path_name
 * @return
 */
size_t load_mmt_sec_rule( rule_info_t const*const ** plugins_arr, const char *plugin_path_name ){
	__check_null( plugin_path_name, 0 );
	size_t plugin_index;

	//this .so is opening
	//this happens when #load_mmt_sec_rules is called many times
	plugin_index = _find_plugin( plugin_path_name );
	if( plugin_index < plugins_count ){
		*plugins_arr = plugins[ plugin_index ].original_rules;
		return plugins[ plugin_index ].original_rules_count ;
	}

	void *lib = dlopen( plugin_path_name, RTLD_NOW );

	rule_info_t const* tmp_array;
	rule_info_t const** original_rules_array;
	rule_info_t const** rules_array;

	size_t size, i, index = 0, p_index, r_index;
	plugin_t *plugin;
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

	mmt_assert( plugins_count < MAX_PLUGIN_COUNT, "Support maximally %d plugins", MAX_PLUGIN_COUNT );

	size = mmt_sec_get_plugin_info( &tmp_array );
	original_rules_array = malloc( sizeof( rule_info_t *) * size );
	for( i=0; i<size; i++ ){
		if( tmp_array[i].version->index < required_plugin )
			mmt_warn( "Ignored rule %d as it is not up to date.\nRule description: %s",
					tmp_array[i].id,
					tmp_array[i].description );
		else
			original_rules_array[ index++ ] = & (tmp_array[i] );
	}

	*plugins_arr = original_rules_array;

	plugin = &plugins[ plugins_count ];

	plugin->original_rules       = original_rules_array;
	plugin->original_rules_count = index;

	plugin->rules   = malloc( sizeof( void*) *  plugin->original_rules_count );
	mmt_assert( plugin->rules != NULL, "Not enough memory");

	//add distinct rules from #original_rules to #rules
	for( i=0; i<plugin->original_rules_count; i++ ){
		//not exist ?
		if( ! _find_plugin_has_rule_id(plugin->original_rules[i]->id, &p_index, &r_index) ){
			mmt_assert( rules_count < MAX_RULES_COUNT, "Support maximally %d rules", MAX_RULES_COUNT );

			//this rule is fresh
			plugin->rules[ plugin->rules_count ] = plugin->original_rules[i];
			plugin->rules_count ++;

			//total rules
			rules_count ++;
		}else
			mmt_warn( "Rule %d in file %s uses the same id as one rule in %s",
					plugin->original_rules[i]->id,
					plugin_path_name,
					plugins[ p_index ].path );
	}

	plugin->path    = strdup( plugin_path_name );
	plugin->dl_lib  = lib;
	plugins_count ++;

	//execute on_load function inside each .so file
	void ( *on_load ) () = dlsym ( lib, "on_load" );
	if( on_load != NULL )
		on_load();
	//else
	//	mmt_debug("Not found on_load on %s", plugin_path_name);

	return size;
}

/**
 * Close a plugin
 * @param plugin
 */
static inline int _close_plugin( plugin_t *plugin ){
	int ret;
	//execute on_unload function inside the plugin if need
	void ( *on_unload ) () = dlsym ( plugin->dl_lib, "on_unload" );
	if( on_unload != NULL )
		on_unload();
	//else
	//	mmt_debug("Not found on_unload");

	ret = dlclose( plugin->dl_lib );
	if( ret != 0 )
		mmt_warn("Cannot close properly plugin: %s", plugin->path );

	//free memory created by strdup
	free( plugin->path );
	free( plugin->rules );
	free( plugin->original_rules );

	return ret;
}

/**
 * unload a rule
 *
 */
static inline bool _unload_mmt_sec_rule( uint32_t rule_id ){
	size_t rule_index, plugin_index;
	__check_bool( (plugins_count == 0), NO );

	//does not found any rule having id = rule_id
	if( _find_plugin_has_rule_id(rule_id, &plugin_index, &rule_index) == NO )
		return NO;

	//there is only one rule in this plugin => remove the plugin
	if( plugins[ plugin_index ].rules_count <= 1 ){
		//first close the plugin
		_close_plugin( &plugins[plugin_index] );

		//then remove it from array by overriding it by the last element in the array
		plugins_count --;
		plugins[ plugin_index ] = plugins[ plugins_count ];

		return YES;
	}

	plugins[ plugin_index ].rules_count --;
	//remove this rule by replacing it by the last rule then remove the last rule
	plugins[ plugin_index ].rules[ rule_index ] = plugins[ plugin_index ].rules[ plugins[ plugin_index ].rules_count ];
	return YES;
}

/**
 * Public API
 */
size_t unload_mmt_sec_rules( size_t count, const uint32_t* rules_id ){
	size_t ret = 0, i;
	for( i=0; i<count; i++ )
		if( _unload_mmt_sec_rule(rules_id[i]) == YES )
			ret ++;
	return ret;
}

//call when exiting application
__attribute__((destructor))
void unload_mmt_sec_all_rules() {
	size_t i, ret = 0;
	for( i=0; i<plugins_count; i++ )
		ret |= _close_plugin( &plugins[i] );

	if( ret != 0 )
		mmt_warn("Cannot close properly mmt-security .so rules");

	plugins_count = 0;
}
