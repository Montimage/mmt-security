/*
 * multithread version of hiredis
 */

#include "mmt_lib.h"
#ifdef MODULE_REDIS_OUTPUT
#ifndef THREDIS_H
#define THREDIS_H
#include <hiredis/hiredis.h>

typedef struct thredis {
	redisContext* redis;
	pthread_mutex_t mutex;
	pthread_t reader_thread;
	struct redis_wait* wait_head;
	struct redis_wait** wait_tail;
} thredis_t;

thredis_t* thredis_new( redisContext* redis_ctx );
void thredis_close( thredis_t* thredis );
redisReply* thredis_command( thredis_t* thredis, const char* format, ... );

#endif
#endif
