import glob
import sys
import re
import os

if len(sys.argv) != 2:
    print( "Usage: python " + sys.argv[0] + " output_file" )
    sys.exit()
outfile = sys.argv[1]
foutput = open(outfile, 'wb')
foutput.write('<!-- MMT_Security Copyright (C) 2014  Montimage: All rules (last update in April 2017)-->\n')
foutput.write('<beginning>\n')
foutput.write('<embedded_functions><![CDATA[\n')
foutput.write('//each function name should be prefixed by em_ \n#include <string.h> \n#include <stdio.h> \n#include <stdlib.h> \n#include <inttypes.h> \n#include "types_defs.h \n')

#Read all files then write embedded functions
for infile in glob.glob('*.xml'):
    #print infile
    if outfile in infile:
        continue
    finput = open(infile, 'rb')
    flag = 0
    for line in finput: 
        if 'static inline' in line: 
            flag = 1
        if '/embedded_functions' in line: 
            flag = 0
            break
        if (flag==1): 
            foutput.write(line)
    finput.close()
foutput.write(']]></embedded_functions>\n')

#Read all files again to write the properties
for infile in glob.glob('*.xml'):
    #print infile
    if outfile in infile:
        continue
    finput = open(infile, 'rb')
    flag = 0
    for line in finput: 
        if 'Property' in line: 
            flag = 1
        if '</beginning>' in line:
            flag = 0
            break
        if (flag==1): 
            foutput.write(line)
    finput.close()

foutput.write('</beginning>\n')
foutput.close()    