/*
 * mmt_sec_config.c
 *
 *  Created on: 23 nov. 2016
 *      Author: la_vinh
 */
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "config.h"
#include "mmt_lib.h"
#include "plugins_engine.h"

static pthread_spinlock_t spin_lock;

static const char *name[] = {
	[MMT_SEC__CONFIG__INPUT__MAX_MESSAGE_SIZE]       = "input.max_message_size",
	[MMT_SEC__CONFIG__SECURITY__MAX_INSTANCES]       = "security.max_instances",
	[MMT_SEC__CONFIG__SECURITY__SMP__RING_SIZE]      = "security.smp.ring_size",
	[MMT_SEC__CONFIG__OUTPUT__INORGE_DESCRIPTION]    = "output.inorge_description",
	[MMT_SEC__CONFIG__MEMPOOL__MAX_BYTES]            = "mempool.max_bytes",
	[MMT_SEC__CONFIG__MEMPOOL__MAX_ELEMENTS_PER_POOL]= "mempool.max_elements_per_pool"
};

//global configuration
static uint32_t config[] = {
	[MMT_SEC__CONFIG__INPUT__MAX_MESSAGE_SIZE]       = 3000,
	[MMT_SEC__CONFIG__SECURITY__MAX_INSTANCES]       = 100000,
	[MMT_SEC__CONFIG__SECURITY__SMP__RING_SIZE]      = 1000,
	[MMT_SEC__CONFIG__OUTPUT__INORGE_DESCRIPTION]    = 20,
	[MMT_SEC__CONFIG__MEMPOOL__MAX_BYTES]            = 2*1000*1000*1000, //2GB per thread
	[MMT_SEC__CONFIG__MEMPOOL__MAX_ELEMENTS_PER_POOL]= 1000
};

uint32_t mmt_sec_get_config( enum config_att att ){
	uint32_t val;
	if( pthread_spin_lock( &spin_lock ) == 0 ){
		val = config[ att ];
		pthread_spin_unlock( &spin_lock );
		return val;
	}
	return 0;
}

uint32_t mmt_sec_set_config( enum config_att att, uint32_t val ){
	if( pthread_spin_lock( &spin_lock ) == 0 ){
		config[ att ] = val;
		pthread_spin_unlock( &spin_lock );
		return val;
	}
	return 0;
}

const char* mmt_sec_get_config_name( enum config_att att ){
	return name[att];
}

/**
 * remove space leading of a string
 */
#define _trim( x ) while( *x == ' ' || *x == '\t' ) x++;
/**
 * Check whether #line in form of #variable_name = #value
 * If yes, set #variable_ptr = #value
 * @param variable_name
 * @param variable_ptr
 * @param line
 * @return
 */
static int _check_then_set_value( int index, const char *line ){
	const char* variable_name = name[ index ];
	long val;
	uint32_t old_val;

	//jump over spaces
	_trim( line );

	//comment
	if( *line == '#' || *line == '\n' || *line == '\r' || *line == '\0' )
		return 0;

	//compare
	while( *variable_name == *line ){
		variable_name ++;
		line          ++;
	}
	//first part is matched
	if( *variable_name == '\0' && ( *line == ' ' || *line == '\t' || *line == '=' )){

		//jump over spaces
		_trim( line );

		val = atol( line );
		old_val = mmt_sec_get_config( index );
		if( val == old_val )
			return 0;

		mmt_info("update \"%s\" from %d to %ld", name[ index ], old_val , val );

		mmt_sec_set_config( index, val );

		return 0;
	}

	return -1;
}

/**
 * PUBLIC API
 * Load config from file ./mmt-security.conf
 * @return
 */
__attribute__((constructor))
bool mmt_sec_load_default_config(){
	char *line = NULL;
	size_t len = 0;
	int i, n = sizeof( config ) / sizeof( uint32_t );

	if( pthread_spin_init( &spin_lock, PTHREAD_PROCESS_PRIVATE ) != 0){
		mmt_halt("Cannot init spin_lock");
	}

	FILE *file = fopen( "./mmt-security.conf", "r" );
	if( file == NULL )
		file = fopen( INSTALL_DIR "/mmt-security.conf", "r" );

	if( file == NULL )
		return false;

	while ( getline( &line, &len, file ) != -1) {

		for( i=0; i<n; i++ )
			if( _check_then_set_value( i, line ) == 0 )
				break;

		if( i == n )
			mmt_warn("mmt-security.conf is not correct. Unexpected \"%s\"", line );
	}

	fclose( file );
	free( line );

	return true;
}
