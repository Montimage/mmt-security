#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include "math.h"
#define SIZE_HASH_STR 15000

struct StrDataItem {
	char *data;
	uint64_t key;
};

struct StrDataItem* hashArrayStr[SIZE_HASH_STR];

uint64_t hashStr(unsigned char *str)
    {
        uint64_t hash = 5381;
        int c;

        while (c = *str++)
            hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

        return hash;
    }

uint64_t hashint(uint64_t key) {
   return key % SIZE_HASH_STR;
}

struct StrDataItem *search_hash_str(uint64_t key) {
   //get the hash 
   uint64_t hashIndex = hashint(key);
	
   //move in array until an empty
   int while_loop=0;
   while((hashArrayStr[hashIndex] != NULL) && (while_loop < SIZE_HASH_STR)) {
	
      if(hashArrayStr[hashIndex]->key == key)
         return hashArrayStr[hashIndex];
			
      //go to next cell
      ++hashIndex;
      ++while_loop;
		
      //wrap around the table
      hashIndex %= SIZE_HASH_STR;
   }        
	
   return NULL;        
}

int insert_hash_str(struct StrDataItem* item) {

	char *data = item->data;
	uint64_t key = item->key;

   //get the hash 
   int hashIndex = hashint(key);

   //move in array until an empty
   int while_loop = 0;
   while(hashArrayStr[hashIndex] != NULL) {
      //go to next cell
      ++hashIndex;
	  ++while_loop;
	  if (while_loop > SIZE_HASH_STR) {
		  printf("Cannot insert because of full hash array\n");
		  return 0;
	  	  }
      //wrap around the table
      hashIndex %= SIZE_HASH_STR;
   }

   hashArrayStr[hashIndex] = item;
   return 1;
}

int delete_hash_str(struct StrDataItem* item) {
	if (item == NULL) return -1;
	uint64_t key = item->key;

   //get the hash 
   int hashIndex = hashint(key);

   //move in array until an empty
   while(hashArrayStr[hashIndex] != NULL) {
	
      if(hashArrayStr[hashIndex]->key == key) {
         hashArrayStr[hashIndex] = NULL;
         free(hashArrayStr[hashIndex]->data);
         free(hashArrayStr[hashIndex]);
         return 1;
      }
		
      //go to next cell
      ++hashIndex;
		
      //wrap around the table
      hashIndex %= SIZE_HASH_STR;
   }      
	
   return 0;
}

void display_hash_str() {
   int i = 0;

   for(i = 0; i<SIZE_HASH_STR; i++) {

      if(hashArrayStr[i] != NULL)
         printf(" (%ld,%s)",hashArrayStr[i]->key,hashArrayStr[i]->data);
      else
         printf(" ~~ ");
   }

   printf("\n");
}

struct StrDataItem* Str2DataItem(const char *str ){
	   char *token = NULL;
	   struct StrDataItem* item = (struct StrDataItem *) malloc(sizeof(struct StrDataItem));
	   item->data = (char *) malloc(sizeof(char)*32);
	   item->key = 0;
	   strcpy(item->data, str);
	   item->key = hashStr(item->data);
	   //printf("Str to item: Key: %lu. Data: %s. Len: %zu\n", item->key, item->data, strlen(item->data));
	   return item;
}

void init_hashArrayStr(){
	//store signatures in a hash table
		FILE *f_in;
		f_in = fopen("test/hoa/trojan_uri","r");
		if (f_in == NULL)
	        exit(EXIT_FAILURE);

		char * line = (char *) malloc(sizeof(char)*32);
	    size_t len = 0;
	    ssize_t read;

		while ((read = getline(&line, &len, f_in)) != -1) {
			line[strlen(line)-1] = '\0';
			//printf("Lines: %s, Len: %zu\n", line, strlen(line));
			struct StrDataItem* item = Str2DataItem(line);
	   		if (insert_hash_str(item) == 0) printf("Insert failed\n");
	   		//else printf("Insert ok\n");
			}
	    free(line);
	    fclose(f_in);
}

void free_hashArrayStr(){
	int i = 0;
	for (i=0; i<SIZE_HASH_STR; i++){
		   if (hashArrayStr[i] != NULL) {
			   free(hashArrayStr[i]->data);
			   free(hashArrayStr[i]);
			   hashArrayStr[i] = NULL;
		   	   }
	   	   }
}
