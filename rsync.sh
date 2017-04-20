#!/bin/bash

TARGET=/home/server10g/huunghia/mmt-security
USER=root
IP=192.168.0.7

#USER=montimage
#IP=192.168.0.194

#TARGET=/home/server10ga/huunghia/mmt-security
#USER=root
#IP=192.168.0.36

TARGET=/home/mmt/mmt-security
USER=mmt
IP=localhost
PORT=2222


rsync -e "ssh -i /Users/nhnghia/.ssh/id_rsa -p $PORT" -rca ./* .git $USER@$IP:$TARGET

TARGET=/home/server10g/huunghia/mmt-security
USER=root
IP=192.168.0.7
PORT=22

rsync -e "ssh -i /Users/nhnghia/.ssh/id_rsa -p $PORT" -rca ./* .git $USER@$IP:$TARGET

#DEBUG="DEBUG=1"


RUN="make install $DEBUG"

#RUN="cd /home/server10g/huunghia/ && rm \"callgrind.out.*\" ; valgrind --tool=callgrind ./mmt_sec_standalone -t 10_800_116kfps.pcap -c 1 -x '101-1000' -v"
#RUN="make standalone $DEBUG && ./copy mmt_sec_standalone && ssh root@192.168.0.7 \"$RUN\" && ./rcopy \"callgrind*\" "

#TEST="message_t"
#RUN="make test.$TEST DEBUG=1 && ./test.$TEST"

#RUN="make sample_rules"
#RUN="make $DEBUG"

#RUN="make check $DEBUG"

#RUN="make test.loop"

echo "Compiling `pwd` ... on $USER@$IP:$TARGET"

ssh -p $PORT $USER@$IP "cd $TARGET && $RUN"