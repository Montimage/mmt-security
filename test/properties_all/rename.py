import glob
import sys
import re
import os

for infile in glob.glob('*HEAD'):
	print infile
	old_name = infile
	new_name = infile.replace('~HEAD','')
	command = 'mv ' + old_name + ' ' + new_name 
	os.system(command)	

