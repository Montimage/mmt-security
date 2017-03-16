import sys
import re
import time

if len(sys.argv) != 5:
	print( "Usage: " + sys.argv[0] + " p_id_from p_id_to input_file output_file" )
	sys.exit()

p_id_from = int(sys.argv[1])
p_id_to   = int(sys.argv[2])
infile    = sys.argv[3]
outfile   = sys.argv[4]

foutput = open(outfile, 'w', encoding='utf8')
foutput.write("<!--This file is repeated from "+ infile +" -->\n")

rules_count = p_id_from
loop = 0
jump_header = False
inside_hader = True
distinct_rule_count = 0
while rules_count <= p_id_to :
	foutput.write("\n<!-- ================LOOP " + str( loop ) + " ==================-->\n\n");
	loop += 1;
	
	finput = open(infile, 'r', encoding='utf8')
	
	inside_hader = True
	distinct_rule_count = 0
	
	for line in finput:
		
		if inside_hader == True and line.find("<property ") != -1:
			inside_hader = False
			
		if jump_header == True and inside_hader == True:
			continue
		
		if line.find( "</beginning>" ) != -1:
			break;
		
		new_line = re.sub('property_id="\d*"', 'property_id = "' + str( rules_count ) + '"', line );
		if new_line != line:
			rules_count += 1
			distinct_rule_count += 1
			
		foutput.write( new_line )
		
		#we got enough rules
		if rules_count == p_id_to + 1 and line.find("</property>") != -1:
			break
	finput.close()
	
	jump_header = True
	
foutput.write('\n</beginning>\n')

des = time.strftime("%Y/%m/%d %H:%M:%S") + " Generated " + str( p_id_to - p_id_from + 1 ) + " from " + str(distinct_rule_count) + " distinct rules in " + str(loop) + " loops"

foutput.write( "\n<!-- " + des + " -->");
print( des )

foutput.close()