#!/bin/bash
rsync -e "ssh -i /Users/nhnghia/.ssh/id_rsa -p 2222" -rca .git ./src ./test ./Makefile mmt@localhost:/home/mmt/mmt-security

DEBUG="DEBUG=1"

RUN="make standalone $DEBUG ; valgrind --leak-check=yes ./mmt_sec_standalone -t ./test/pcap/test_p1_acdc.pcap"
#RUN="make test.rule $DEBUG; ./security"
RUN="make compile_rule $DEBUG; ./compile_rule rules/2.so test/xml/2.rules_before.xml \"./src/lib -g\""

ssh -p 2222 mmt@localhost "cd /home/mmt/mmt-security; $RUN"