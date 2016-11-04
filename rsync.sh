#!/bin/bash
rsync -e "ssh -i /Users/nhnghia/.ssh/id_rsa -p 2222" -rca .git ./src ./test ./Makefile mmt@localhost:/home/mmt/mmt-security

DEBUG="DEBUG=1"

RUN="make standalone $DEBUG ; time ./mmt_sec_standalone -t /media/sf_share_vbox/pcap/test_p4_acdc.pcap"
#RUN="make test.rule $DEBUG; ./security"
RUN="make compile_rule $DEBUG; ./compile_rule rules/evasion.c test/xml/properties_evasion.xml -c"

ssh -p 2222 mmt@localhost "cd /home/mmt/mmt-security; $RUN"