#!/bin/bash

echo "Compiling `pwd` ... "

#rsync -e "ssh -i /Users/nhnghia/.ssh/id_rsa -p 2222" -rca ./* .git mmt@localhost:/home/mmt/mmt-security
#ssh -p 2222 mmt@localhost "cd mmt-security; make clean PCAP=1; make PCAP=1 && ./copy security"

#exit 0

TARGET=/home/server10g/huunghia/mmt-security
USER=root
IP=192.168.0.7

#USER=montimage
#IP=192.168.0.194

#TARGET=/home/server10ga/huunghia/mmt-security
#USER=root
#IP=192.168.0.36

rsync -e "ssh -i /Users/nhnghia/.ssh/id_rsa" -rca ./* .git $USER@$IP:$TARGET

#DEBUG="DEBUG=1"

RUN="make install"

ssh $USER@$IP "cd $TARGET && $RUN"