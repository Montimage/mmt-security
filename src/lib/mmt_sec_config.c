/*
 * mmt_sec_config.c
 *
 *  Created on: 23 nov. 2016
 *      Author: la_vinh
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "mmt_sec_config.h"

mmt_sec_config_struct_t get_mmt_sec_config(char *filename)
{
        mmt_sec_config_struct_t configstruct;
        FILE *file = fopen (filename, "r");

        if (file != NULL)
        {
			char line[256];
			int linenum = 0;

                while(fgets(line, 256, file) != NULL)
                {
					   char para[256];
					   int val;
                       if(line[0] == '#') continue;
                       if(sscanf(line, "%s %d", para, &val) != 2){
							fprintf(stderr, "Syntax error, line: %d\n", linenum);
							continue;
							}
					    if(linenum==0) configstruct.nb_thr_sec =  val;
					    else if(linenum==1) configstruct.portno = val;
					    else if(linenum==2) configstruct.threshold_size = val;
					    else if(linenum==3) configstruct.threshold_time =  val;
					    linenum++;
                 } // End while

        } // End if file
       fclose(file);
       return configstruct;
}
