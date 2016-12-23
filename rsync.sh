#!/bin/bash
rsync -e "ssh -i /Users/nhnghia/.ssh/id_rsa -p 2222" -rca .git ./src ./test ./Makefile ./*.conf mmt@localhost:/home/mmt/mmt-security

DEBUG="DEBUG=1"

RUN="make standalone $DEBUG ; valgrind --leak-check=yes ./mmt_sec_standalone -t ./test/pcap/test_p1_acdc.pcap"
#RUN="make test.spsc; ./copy test.spsc"
RUN="make compile_rule $DEBUG; ./compile_rule rules/all.so test/xml/properties_all_09dec2016.xml \"-I./src/dpi -g\""

RUN="make standalone $DEBUG"

#RUN="make test.tcp_server; ./copy test.tcp_server"
#RUN="make test.receiving_report; ./copy test.receiving_report"
RUN="make sec_server_no_reorder $DEBUG; ./copy mmt_sec_no_reordering "

ssh -p 2222 mmt@localhost "cd /home/mmt/mmt-security; $RUN"