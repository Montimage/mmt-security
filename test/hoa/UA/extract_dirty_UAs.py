##########################################
#Extract blacklisted User-Agent strings representing R (Robot, crawler, spider) and S (Spam or bad bot)#
##########################################

import sys
import re

infile = sys.argv[1]
outfile = sys.argv[2]
foutput = open(outfile, 'wb')
finput = open(infile,'rb')

list_UA = []
flag = 0
for line in finput:
    	if flag == 0 and '<String>' in line:
		ua = ''
		ua += re.findall(r'<String>(.*?)</String>',line)[0]
    		if ua == '' or len(ua) > 31: 
        		continue
    		if not ua in list_UA:
        		#print ua
        		list_UA.append(ua) 
			flag = 1
			continue
	if flag == 1 and '<Type>' in line: 
		if ('<Type>R</Type>' in line or '<Type>S</Type>' in line):
			#print 'One malicious UA string found'
			flag =0 
			continue
		else:
			list_UA.pop(-1)
			flag = 0
for ua in list_UA: 
	foutput.write(ua +'\n')
foutput.close()
finput.close()
