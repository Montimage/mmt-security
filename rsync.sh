#!/bin/bash
rsync -e "ssh -i /Users/nhnghia/.ssh/id_rsa -p 2222" -rca ./src ./test ./Makefile mmt@localhost:/home/mmt/mmt-security

#RUN="./mmt_sec_standalone -t ../pcap_files/arp_spoof.pcap"
ssh -p 2222 mmt@localhost "cd /home/mmt/mmt-security; make standalone; $RUN"
