#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include "math.h"
#define SIZE_HASH_IP 15000

struct DataItem {
	char *data;
	uint64_t key;
};

struct DataItem* hashArrayIPAdd[SIZE_HASH_IP];

uint64_t hashCode(uint64_t key) {
   return key % SIZE_HASH_IP;
}

struct DataItem *search_hash_ip(uint64_t key) {
   //get the hash 
   uint64_t hashIndex = hashCode(key);
	
   //move in array until an empty
   int while_loop=0;
   while((hashArrayIPAdd[hashIndex] != NULL) && (while_loop < SIZE_HASH_IP)) {
	
      if(hashArrayIPAdd[hashIndex]->key == key)
         return hashArrayIPAdd[hashIndex];
			
      //go to next cell
      ++hashIndex;
      ++while_loop;
		
      //wrap around the table
      hashIndex %= SIZE_HASH_IP;
   }        
	
   return NULL;        
}

int insert_hash_ip(struct DataItem* item) {

	char *data = item->data;
	uint64_t key = item->key;

   //get the hash 
   int hashIndex = hashCode(key);

   //move in array until an empty
   int while_loop = 0;
   while(hashArrayIPAdd[hashIndex] != NULL) {
      //go to next cell
      ++hashIndex;
	  ++while_loop;
	  if (while_loop > SIZE_HASH_IP) {
		  printf("Cannot insert because of full hash array\n");
		  return 0;
	  	  }
      //wrap around the table
      hashIndex %= SIZE_HASH_IP;
   }

   hashArrayIPAdd[hashIndex] = item;
   return 1;
}

int delete_hash_ip(struct DataItem* item) {
	if (item == NULL) return -1;
	uint64_t key = item->key;

   //get the hash 
   int hashIndex = hashCode(key);

   //move in array until an empty
   while(hashArrayIPAdd[hashIndex] != NULL) {
	
      if(hashArrayIPAdd[hashIndex]->key == key) {
         hashArrayIPAdd[hashIndex] = NULL;
         free(hashArrayIPAdd[hashIndex]->data);
         free(hashArrayIPAdd[hashIndex]);
         return 1;
      }
		
      //go to next cell
      ++hashIndex;
		
      //wrap around the table
      hashIndex %= SIZE_HASH_IP;
   }      
	
   return 0;
}

void display_hash_ip() {
   int i = 0;

   for(i = 0; i<SIZE_HASH_IP; i++) {

      if(hashArrayIPAdd[i] != NULL)
         printf(" (%ld,%s)",hashArrayIPAdd[i]->key,hashArrayIPAdd[i]->data);
      else
         printf(" ~~ ");
   }

   printf("\n");
}
struct DataItem* ipStr2DataItem(char *ipAdd ){
	   char *token = NULL;
	   char ipAddr[16];
	   struct DataItem* item = (struct DataItem *) malloc(sizeof(struct DataItem));
	   item->data = (char *) malloc(sizeof(char)*16);
	   item->key = 0;
	   memcpy(item->data, ipAdd, 15);
	   item->data[15] = '\0';
	   strcpy(ipAddr,item->data);
	   token = strtok(ipAddr, ".");
	   int i = 0;
	   while ((token != NULL) && (i<4)) {
		   	   	   //printf("Token:%s\n", token);
	   			   if(i==0) item->key += 16777216U*atoi(token);
	   			   if(i==1) item->key += 65536U*atoi(token);
	   			   if(i==2) item->key += 256U*atoi(token);
	   			   if(i==3) item->key += 1U*atoi(token);
	   			   i += 1;
		   	   	   token = strtok(NULL, ".");
	   				}
	   printf("Str to item: Key: %ld. Data: %s\n", item->key, item->data);
	   return item;
}

void init_hashArrayIPAdd(){
	//store signatures in a hash table
		FILE *f_in;
		f_in = fopen("test/hoa/botcc_ip","r"); //TODO: This should be configurable
		if (f_in == NULL)
	        exit(EXIT_FAILURE);

		char * line = (char *) malloc(sizeof(char)*16);
	    size_t len = 0;
	    ssize_t read;

		while ((read = getline(&line, &len, f_in)) != -1) {
			//printf("Lines: %s", line);
	        struct DataItem* item = ipStr2DataItem(line);
	   		if (insert_hash_ip(item) == 0) printf("Insert failed\n");
	   		//else printf("Insert ok\n");
			}
	    free(line);
	    fclose(f_in);
}

void free_hashArrayIPAdd(){
	int i = 0;
	for (i=0; i<SIZE_HASH_IP; i++){
		   if (hashArrayIPAdd[i] != NULL) {
			   free(hashArrayIPAdd[i]->data);
			   free(hashArrayIPAdd[i]);
			   hashArrayIPAdd[i] = NULL;
		   	   }
	   	   }
}
