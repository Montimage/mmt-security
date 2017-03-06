import sys

loop = int(sys.argv[1])
infile = sys.argv[2]
outfile= sys.argv[3]

print loop


foutput = open(outfile, 'wb')
foutput.write('<beginning>\n')
nb_r = 1
for i in xrange(loop):
	finput = open(infile, 'rb')
	for line in finput:
		elements = line.split(' ')
		for element in elements:
			if element == 'property_id=\"\"':
				#print "A property found"
				element = 'property_id=\"'+str(nb_r)+'\"'
				foutput.write(element + ' ')
				nb_r += 1
			else: 
				foutput.write(element + ' ')
	finput.close()
foutput.write('</beginning>\n')
foutput.close()
