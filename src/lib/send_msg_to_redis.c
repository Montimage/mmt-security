/*
 * print_verdict.c
 *
 *  Created on: Dec 9, 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include "thredis.h"
#include "mmt_lib.h"

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
	if (redis == NULL){
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
		if (thredis == NULL){
			thredis = thredis_new(redis);
			if(thredis == NULL) {
				mmt_error("Thredis wrapper thredis_new failed\n");
				exit(0);
			}
		}
	}
}

inline void send_message_to_redis (const char * message) {
	//printf("---> report to redis: %s\n%s\n",REDIS_CHANNEL_NAME, message);
	// Publish to redis if it is enabled
	if ( likely( thredis != NULL)) {
		// Publish an event
		redisReply *reply;

		reply = thredis_command( thredis, "PUBLISH %s [%s]", REDIS_CHANNEL_NAME, message );

		if(reply == NULL){
			mmt_error("Redis command error: can't allocate reply context\n");
		}else{
			if(thredis->redis->err != 0){
				mmt_error("Redis command error nb %d: %s\n",thredis->redis->err, thredis->redis->errstr);
			}
			if(reply->type == REDIS_REPLY_ERROR){
				mmt_error("Redis reply error nb %d: %s\n", reply->type, reply->str);
			}
			freeReplyObject(reply);
		}
	}
}
