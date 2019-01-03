#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include "math.h"
#include "hash_table_botcc.h"

int main() {
   int i=0;

//   int i=1;
//   for (i=0; i<12; i++){
//	   struct DataItem* item;
//	   item = (struct DataItem *) malloc(sizeof(struct DataItem));
//	   item->key= i;
//	   item->data = i+20;
//	   if (insert(item) != 1) free(item);
//	   }

   //store signatures in a hash table
   	FILE *f_in;
   	f_in = fopen("botcc_ip","r");
   	if (f_in == NULL)
           exit(EXIT_FAILURE);

   	char * line = NULL;
       size_t len = 0;
       ssize_t read;

   	while ((read = getline(&line, &len, f_in)) != -1) {
        //printf("Lines: %s", line);
   		struct DataItem* item = ipStr2DataItem(line);
   		if (insert_hash_ip(item) == 0) printf("Insert failed\n");
   		}
      if (line) free(line);
      fclose(f_in);

      //test search
   struct DataItem* new_item;
   new_item = search_hash_ip(1653576877);
   if (new_item != NULL) printf("Item found: Key: %lu. Data: %s\n", new_item->key, new_item->data);
   else printf("Item not found\n");

   //free everything before quitting
   for (i=0; i<SIZE_HASH_IP; i++){
	   if (hashArrayIPAdd[i] != NULL) {
		   free(hashArrayIPAdd[i]->data);
		   free(hashArrayIPAdd[i]);
		   hashArrayIPAdd[i] = NULL;
	   	   }
   	   }
}

