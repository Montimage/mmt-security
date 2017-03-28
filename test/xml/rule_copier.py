#This script is to multiply one rule to N rules (copied)
#Command: python rule_copier.py <nb_of rules> <in_file> <outfile>

import sys

loop = int(sys.argv[1])
infile = sys.argv[2]
outfile= sys.argv[3]

foutput = open(outfile, 'wb')
nb_r = 1
flag = 0 #to determine if we are inside the embedded functions?
nb_l_ef = 0 #number of lines before '</embedded_functions>' 

#Read and write the thing before '</embedded_functions>' first 
finput = open(infile, 'rb')
for line in finput:
	if  '</embedded_functions>' in line:
		foutput.write(line)
		nb_l_ef += 1
		break
	foutput.write(line)
	nb_l_ef += 1
finput.close()

for i in xrange(loop):
	nb_line = 0
	finput = open(infile, 'rb')
	for line in finput:
		nb_line += 1
		if nb_line < (nb_l_ef+1):
			continue #do not take into account the thing before '</embedded_functions>' 
		elements = line.split(' ')
		for element in elements:
			if 'property_id=\"' in element:
				element = 'property_id=\"'+str(nb_r)+'\"'
				foutput.write(element + ' ')
				nb_r += 1
				continue
			if '</beginning>' in element:
				continue
			foutput.write(element + ' ')
	finput.close()
foutput.write('</beginning>\n')
foutput.close()
