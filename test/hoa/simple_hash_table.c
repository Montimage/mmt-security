#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define SIZE 10

struct DataItem {
	//char data[16];
	//uint64_t key;
	int data;
	int key;

};

struct DataItem* hashArray[SIZE]; 

int hashCode(int key) {
   return key % SIZE;
}

struct DataItem *search(int key) {
   //get the hash 
   int hashIndex = hashCode(key);  
	
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

   int data = item->data;
   int key = item->key;

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
   int key = item->key;

   //get the hash 
   int hashIndex = hashCode(key);

   //move in array until an empty
   while(hashArray[hashIndex] != NULL) {
	
      if(hashArray[hashIndex]->key == key) {
         hashArray[hashIndex] = NULL;
         free(item);
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
         printf(" (%d,%d)",hashArray[i]->key,hashArray[i]->data);
      else
         printf(" ~~ ");
   }
	
   printf("\n");
}

int main() {

   int i=1;
   for (i=0; i<12; i++){
	   struct DataItem* item;
	   item = (struct DataItem *) malloc(sizeof(struct DataItem));
	   item->key= i;
	   item->data = i+20;
	   if (insert(item) != 1) free(item);
	   display();
   }
 struct DataItem* item = search(2);

   if(item != NULL) {
      printf("Element found: %d\n", item->data);
   } else {
      printf("Element not found\n");
   }

   delete(item);
   display();
   item = search(2);

   if(item != NULL) {
      printf("Element found: %d\n", item->data);
   } else {
      printf("Element not found\n");
   }

   //free everything before quitting
   for (i=0; i<SIZE; i++){
	   if (hashArray[i] != NULL) {
		   free(hashArray[i]);
		   hashArray[i] = NULL;
	   	   }
   	   }
   display();
}
