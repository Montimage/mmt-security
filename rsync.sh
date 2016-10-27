#!/bin/bash
rsync -e "ssh -i /Users/nhnghia/.ssh/id_rsa -p 2222" -rca ./src ./test ./Makefile mmt@localhost:/home/mmt/mmt-security

RUN="make standalone; time ./mmt_sec_standalone -t ../pcap_files/bigFlows.pcap > /media/sf_share_vbox/output/acdc_new.txt"
#RUN="make test.rule; ./security"
#RUN="make gen_plugin;"
ssh -p 2222 mmt@localhost "cd /home/mmt/mmt-security; $RUN"
