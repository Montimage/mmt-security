#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include "math.h"
#include "hash_table_str.h"

int main() {
   int i=0;

   //store signatures in a hash table
   	FILE *f_in;
   	f_in = fopen("trojan_uri","r");
   	if (f_in == NULL)
           exit(EXIT_FAILURE);

   	char * line = NULL;
       size_t len = 0;
       ssize_t read;

   	while ((read = getline(&line, &len, f_in)) != -1) {
        //printf("Lines: %s", line);
   		struct StrDataItem* item = Str2DataItem(line);
   		if (insert_hash_str(item) == 0) printf("Insert failed\n");
   		}
      if (line) free(line);
      fclose(f_in);

      //test search
   struct StrDataItem* new_item;
   new_item = search_hash_str(14362212337035324983U);
   if (new_item != NULL) printf("Item found: Key: %lu. Data: %s\n", new_item->key, new_item->data);
   else printf("Item not found\n");

   //free everything before quitting
   free_hashArrayStr();
}

