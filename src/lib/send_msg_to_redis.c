/*
 * print_verdict.c
 *
 *  Created on: Dec 9, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */
#include <stdio.h>
#include <string.h>
#include "mmt_lib.h"

#ifdef MODULE_REDIS_OUTPUT
#include <time.h>
#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include "thredis.h"

#define REDIS_CHANNEL_NAME "security.report"

static thredis_t* thredis = NULL;
/**
 * Connects to redis server and exits if the connection fails
 *
 * @param hostname hostname of the redis server
 * @param port port number of the redis server
 *
 * In short, to subscribe to "localhost" channel:*/

void init_redis ( const char *hostname, int port ) {
	struct timeval timeout = { 1, 500000 }; // 1.5 seconds
	redisContext *redis = NULL;

	// Connect to redis if not yet done
	if (thredis == NULL){
		redis = redisConnectWithTimeout(hostname, port, timeout);
		if (redis == NULL || redis->err) {
			if (redis) {
				printf("Connection error nb %d: %s\n", redis->err, redis->errstr);
				redisFree(redis);
			} else {
				printf("Connection error: can't allocate redis context\n");
			}
			exit(0);
		}
		thredis = thredis_new(redis);
		if(thredis == NULL) {
			mmt_error("Thredis wrapper thredis_new failed\n");
			exit(0);
		}
	}
}

void send_message_to_redis (const char * message) {
	//printf("---> report to redis: %s\n%s\n",REDIS_CHANNEL_NAME, message);
	// Publish to redis if it is enabled
	if ( likely( thredis != NULL)) {
		// Publish an event
		redisReply *reply;

		reply = thredis_command( thredis, "PUBLISH %s [%s]", REDIS_CHANNEL_NAME, message );

		if( unlikely( reply == NULL )){
			mmt_error("Redis command error: can't allocate reply context\n");
		}else{
			if( unlikely( thredis->redis->err != 0 )){
				mmt_error("Redis command error nb %d: %s\n",thredis->redis->err, thredis->redis->errstr);
			}
			if( unlikely( reply->type == REDIS_REPLY_ERROR )){
				mmt_error("Redis reply error nb %d: %s\n", reply->type, reply->str);
			}

			freeReplyObject(reply);
		}
	}
}

#pragma message("Enable module: Output to redis")
#else
#pragma message("Disable module: Output to redis")

void init_redis ( const char *hostname, int port ) {
	mmt_warn("Module output to redis is not available");
}

void send_message_to_redis (const char * message){}
#endif
