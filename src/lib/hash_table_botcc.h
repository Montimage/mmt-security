#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include "math.h"
#define SIZE 15000

struct DataItem {
	char *data;
	uint64_t key;
};

struct DataItem* hashArray[SIZE]; 

int hashCode(uint64_t key) {
   return key % SIZE;
}

struct DataItem *search(int key) {
   //get the hash 
   uint64_t hashIndex = hashCode(key);
	
   //move in array until an empty
   int while_loop=0;
   while((hashArray[hashIndex] != NULL) && (while_loop < SIZE)) {
	
      if(hashArray[hashIndex]->key == key)
         return hashArray[hashIndex]; 
			
      //go to next cell
      ++hashIndex;
      ++while_loop;
		
      //wrap around the table
      hashIndex %= SIZE;
   }        
	
   return NULL;        
}

int insert(struct DataItem* item) {

	char *data = item->data;
	uint64_t key = item->key;

   //get the hash 
   int hashIndex = hashCode(key);

   //move in array until an empty
   int while_loop = 0;
   while(hashArray[hashIndex] != NULL) {
      //go to next cell
      ++hashIndex;
	  ++while_loop;
	  if (while_loop > SIZE) {
		  printf("Cannot insert because of full hash array\n");
		  return 0;
	  	  }
      //wrap around the table
      hashIndex %= SIZE;
   }

   hashArray[hashIndex] = item;
   return 1;
}

int delete(struct DataItem* item) {
	if (item == NULL) return -1;
	uint64_t key = item->key;

   //get the hash 
   int hashIndex = hashCode(key);

   //move in array until an empty
   while(hashArray[hashIndex] != NULL) {
	
      if(hashArray[hashIndex]->key == key) {
         hashArray[hashIndex] = NULL;
         free(hashArray[hashIndex]->data);
         free(hashArray[hashIndex]);
         return 1;
      }
		
      //go to next cell
      ++hashIndex;
		
      //wrap around the table
      hashIndex %= SIZE;
   }      
	
   return 0;
}

void display() {
   int i = 0;

   for(i = 0; i<SIZE; i++) {

      if(hashArray[i] != NULL)
         printf(" (%ld,%s)",hashArray[i]->key,hashArray[i]->data);
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
	   //printf("Str to item: Key: %ld. Data: %s\n", item->key, item->data);
	   return item;
}
