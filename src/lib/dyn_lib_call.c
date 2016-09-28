/*
 * dyn_lib_call.c
 *
 *  Created on: 19 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifdef WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#ifdef WIN32
#define LIB_NAME "libembedded_functions.dll"
#else
#define LIB_NAME "libembedded_functions.so"
#endif

#include "mmt_alloc.h"

//TODO cache lib_pointer

int funct_get_return_type_and_size(int *size, char *lib_name, char *funct_name){
#ifdef WIN32
	HMODULE lib_pointer;
#else
	void * lib_pointer;
#endif
	void *(*embedded_function)();
	int type = 0;
#ifdef WIN32
	lib_pointer = LoadLibrary(lib_name);
	if (! lib_pointer) {
		FARPROC initializer = GetProcAddress(lib_pointer, "get_data_type_of_funct_return_value");
		*(void **) (&embedded_function) = initializer;
		int * temph = (int*) embedded_function(funct_name, size);
		type = *temph;
		xfree(temph);
	}
#else
	lib_pointer = dlopen(lib_name, RTLD_LAZY);
	if ( lib_pointer ) {
		*(void **) (&embedded_function) = dlsym(lib_pointer, "get_data_type_of_funct_return_value");
		int * temph = (int*) embedded_function(funct_name, size);
		type = *temph;
		mmt_free(temph);
	}
#endif
	return type;
}


void *funct_execute( const char *lib_name, const char *fn_name, size_t param_size, const void **param_ptr,  size_t data_size){
	void *lib_pointer = NULL;
	void *(*embedded_function)();
	void * ihandle = NULL;
	void * result_data = NULL;
#ifdef WIN32
	lib_pointer = LoadLibrary(lib_name);
#else
	lib_pointer = dlopen(lib_name, RTLD_LAZY);
#endif

	if ( lib_pointer ) {
#ifdef WIN32
		FARPROC initializer = GetProcAddress(lib_pointer, funct_name);
		*(void **) (&embedded_function) = initializer;
#else
		*(void **) (&embedded_function) = dlsym(lib_pointer, fn_name);
#endif

		switch (param_size) {
		case 0: ihandle = embedded_function();
			break;
		case 1: ihandle = embedded_function( param_ptr[0]);
			break;
		case 2: ihandle = embedded_function(param_ptr[0], param_ptr[1]);
			break;
		case 3: ihandle = embedded_function(param_ptr[0], param_ptr[1], param_ptr[2]);
			break;
		case 4: ihandle = embedded_function(param_ptr[0], param_ptr[1], param_ptr[2], param_ptr[3]);
			break;
		}
		result_data = mmt_malloc(data_size);
		memcpy(result_data, ihandle, data_size);
		mmt_free(ihandle);

#ifdef WIN32
		FreeLibrary(lib_pointer);
#else
		dlclose(lib_pointer);
#endif
		//caller needs to free return value
		return result_data;
    }
    return NULL;
}
