#!/bin/bash
rsync -e "ssh -i /Users/nhnghia/.ssh/id_rsa -p 2222" -rca ./src ./test ./Makefile mmt@localhost:/home/mmt/mmt-security

RUN="make standalone; #time ./mmt_sec_standalone -t ../pcap_files/bigFlows.pcap > /media/sf_share_vbox/output/acdc_new.txt"
#RUN="make test.rule; ./security"
RUN="make gen_plugin; ./gen_plugin rules/properties_acdc.so test/xml/properties_acdc.xml"
ssh -p 2222 mmt@localhost "cd /home/mmt/mmt-security; $RUN"
