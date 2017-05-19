#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    FILE * fp;
    char* line=NULL;
    size_t len = 0;
    ssize_t read;
    int size=0;

    fp = fopen("botcc_ip", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    while ((read = getline(&line, &len, fp)) != -1) {
        printf("Retrieved line of length %zu :\n", read);
	size += 1;
        printf("Line %d: %s", size, line);

    }

    fclose(fp);
    if (line)
        free(line);
    exit(EXIT_SUCCESS);
}
