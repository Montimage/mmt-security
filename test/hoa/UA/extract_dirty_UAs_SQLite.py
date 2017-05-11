##########################################
#Extract blacklisted User-Agent strings representing R (Robot, crawler, spider) and S (Spam or bad bot)#
##########################################

import sys
import re
import sqlite3

infile = sys.argv[1]
finput = open(infile,'rb')

list_UA = []
flag = 0

#connect to the database and create the table
conn = sqlite3.connect('db_blacklisted_UA.sqlite')
conn.text_factory = str #to accept also strange characters 
#print "Opened database successfully";
cursor = conn.cursor()
cursor.execute("CREATE TABLE blacklisted_UA (UA text)")

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
	#insert into SQLite here
	query = '''INSERT INTO blacklisted_UA VALUES ("''' + ua + '''")'''
	print query
	cursor.execute(query)
conn.commit()
conn.close()
finput.close()
