#!/bin/bash
rsync -e "ssh -i /Users/nhnghia/.ssh/id_rsa -p 2222" -rca .git ./src ./test ./Makefile ./*.conf mmt@localhost:/home/mmt/mmt-security

#DEBUG="DEBUG=1"

RUN="make standalone $DEBUG ; valgrind --leak-check=yes ./mmt_sec_standalone -t ./test/pcap/test_p1_acdc.pcap"

#RUN="make clean; make test.spsc && ./copy test.spsc"

#RUN="make compile_rule $DEBUG; ./compile_rule rules/all.so test/xml/properties_all_09dec2016.xml \"-I./src/dpi -g\""

RUN="make clean; make $DEBUG -j2 && ./copy mmt_sec_server && ./copy mmt_sec_standalone"

#RUN="make test.tcp_server; ./copy test.tcp_server"
#RUN="make test.receiving_report; ./copy test.receiving_report"
#RUN="make sec_server_no_reorder $DEBUG; ./copy mmt_sec_no_reordering "

#RUN="rm test.expand_range; make test.expand_range $DEBUG && ./test.expand_range"

#RUN="make test.malloc $DEBUG ; valgrind --leak-check=yes ./test.malloc"

#RUN="make && ./compile_rule rules/properties.so test/xml/properties_clone_id.xml"

ssh -p 2222 mmt@localhost "cd /home/mmt/mmt-security; $RUN"