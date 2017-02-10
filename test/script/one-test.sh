#!/bin/bash

#run the test during 5 minutes
INTERVAL=80


if [[ $# != 6 && $# != 7 ]]; then
  echo "usage: $0 test_id bandwidth pkt_size attack_rate probe_core rules_count"
  exit 0
fi

export TZ=Europe/Paris

TEST_ID=$1
BANDWIDTH=$2
PKT_SIZE=$3
ATTACK_RATE=$4
PROBE_CORE=$5
RULES_COUNT=$6


DESCRIPTION="bandwidth $BANDWIDTH, pkt-size $PKT_SIZE, attack rate $ATTACK_RATE, #core $PROBE_CORE, #rules $RULES_COUNT"

#check input parameters
case $PKT_SIZE in
  600|800|1000) ;;
  *) echo "pkt_size must be 600 or 800 or 1000" && exit 1 ;;
esac

case $ATTACK_RATE in
  normal|10|20|30|40|50) ;;
  *) echo "attack_rate must be normal or 10 or 20 or 30 or 40 or 50" && exit 1 ;;
esac

PROBE_CORE_MASK=AAAAAAAAAB 
case $PROBE_CORE in
  8) PROBE_CORE_MASK=AAAAB ;;
  16) ;;
  *) echo "probe_core must be 8 or 16" && exit 1 ;;
esac

#path on remote server in which we run the tests
APP_PATH="/opt/mmt/test"

LOG_PATH="logs"

OUTPUT=$LOG_PATH/output.csv

#gnuplot
A_RATE=$ATTACK_RATE
if [[ "$A_RATE" == "normal" ]]; then
  A_RATE="0"
fi
GRAPH_TITLE="$(date +%Y-%m-%d\ %H:%M:%S)\nbandwidth $BANDWIDTH Mbps, pkt-size $PKT_SIZE Byte, attack rate $A_RATE%,\n #core $PROBE_CORE, #rules $RULES_COUNT"
START=$(date +%s)
END=$((START+INTERVAL+5))
XRANGE="$START:$END"

date >  $LOG_PATH/$TEST_ID.txt
echo "test $TEST_ID, $DESCRIPTION" | tee -a $LOG_PATH/$TEST_ID.txt

CONFIG="$TEST_ID,$BANDWIDTH,$PKT_SIZE,$ATTACK_RATE,$PROBE_CORE,$RULES_COUNT"

# note:
# parameter of run-proc.sh
# $1 : directory
# $2 : program name
# $3 : parameters
# $4 : interval (in second)
# $5 : output



# $1 : server (user@ip)
# $2 : program
# $3 : param
# $4 : id
function run () {
  ssh $1 "mkdir -p $APP_PATH &> /dev/null"
  #copy run-file
  scp run-proc.sh $1:/$APP_PATH > /dev/null
  #copy program to server
  scp apps/$2 $1:$APP_PATH/$2   > /dev/null
  #run
  ssh $1 "chmod +x $APP_PATH/run-proc.sh && $APP_PATH/run-proc.sh $APP_PATH $2 \"$3\" $INTERVAL $TEST_ID.$2$4"
  #get log
  scp $1:$APP_PATH/$TEST_ID.$2$4* $LOG_PATH/ > /dev/null
  #draw graph
  ./draw.sh $LOG_PATH/$TEST_ID.$2$4.stat $XRANGE "$GRAPH_TITLE" > $LOG_PATH/$TEST_ID.$2$4.png
}


# $1 : IP server
# $2 : id
function run_probe () {
  SERVER="root@$1"
  PROBE_CONF="probe.conf"
  APP_PARAM="-c $PROBE_CORE_MASK -- -c $APP_PATH/$PROBE_CONF"
  PROGRAM="probe"

  #update thread_number in probe.conf
  sed -e "s/^thread-nb.*/thread-nb=$PROBE_CORE/" $PROBE_CONF > probe_tmp.conf

  scp probe_tmp.conf $SERVER:$APP_PATH/$PROBE_CONF > /dev/null


  run $SERVER $PROGRAM "$APP_PARAM" $2

  FILE=$LOG_PATH/$TEST_ID.$PROGRAM$2

  #filter output: probe_id,pkt_proc,#drop,%drop,#error,#pkt_recv
  PKT=`grep    "\[mmt-probe-0\]{" $FILE.txt | sed "s/\[mmt-probe-0\]{//" | sed "s/}//" `
  #reports_sent
  REPORT=`grep "\[mmt-probe-3\]{" $FILE.txt | sed "s/\[mmt-probe-3\]{//" | sed "s/}//"`
  #queue_id,pkt
  #QUEUE=`grep "\[mmt-probe-1\]{" $FILE.txt | sed "s/\[mmt-probe-1\]{//" | sed "s/}/,/" | sort | xargs`

  #when we can not get output of probe
  if [[ -z "$PKT" ]]; then
    PKT=",,,,,"
  fi
  echo "$PKT,$REPORT" > $FILE.txt.tmp
}


# $1 : IP server
# $2 : id
function run_security () {
  SERVER="root@$1"
  START_INDEX=$(($RULES_COUNT+1))
  APP_PARAM="-p /opt/mmt/probe/bin/mysocket -c 38-85 -m (0:${START_INDEX}-1000) -n 4 -v"
  PROGRAM="sec"

  scp -r rules $SERVER:$APP_PATH/ > /dev/null

  run $SERVER $PROGRAM "$APP_PARAM" $2

  FILE=$LOG_PATH/$TEST_ID.$PROGRAM$2

  #filter output
  ALERTS=`grep "connection sent"  $FILE.txt | cut -d 'd' -f 2 | cut -d 'a' -f1 | xargs  | sed -e 's/\ /+/g' | bc`

  REPORT=`grep "connection sent"  $FILE.txt | cut -d 't' -f 4 | cut -d 'r' -f1 | xargs  | sed -e 's/\ /+/g' | bc`

  echo "$ALERTS,$REPORT" > $FILE.txt.tmp
}


# $1 : IP server
function run_lb () {
  SERVER="root@$1"
  CONF="lb.conf"
  APP_PARAM="-c 0xAAAAAAAAAB -- -c $CONF"
  PROGRAM="lb"

  scp $CONF $SERVER:$APP_PATH/$CONF > /dev/null

  run $SERVER $PROGRAM "$APP_PARAM"

  FILE=$LOG_PATH/$TEST_ID.$PROGRAM

  #filter output: pkt recv, pkt pros, #drop, %drop, #err,%err,?,?,? 
  LB_OUTPUT=`grep "\[mmt-report-1\]{2," $FILE.txt | sed "s/\[mmt-report-1\]{2,//" | sed "s/}//"` 
  #HTTP pkt, non-HTTP pkt
  HTTP=`grep "\[mmt-report-3\]{" $FILE.txt | sed "s/\[mmt-report-3\]{//" | cut -d',' -f3 | xargs | sed -e 's/\ /+/g' | bc` 
  NO_HTTP=`grep "\[mmt-report-3\]{" $FILE.txt | sed "s/\[mmt-report-3\]{//" | cut -d',' -f4 | xargs | sed -e 's/\ /+/g' | bc` 

  #if no report => insert empty
  if [[ -z "$LB_OUTPUT" ]]; then
    LB_OUTPUT=",,,,,,,,"
  fi
  echo "$LB_OUTPUT,$NO_HTTP,$HTTP" > $FILE.txt.tmp

}

# $1 : IP server
function run_traffic_gen () {
  SERVER="root@$1"
  APP_PARAM="-i eth2 --unique-ip --netmap --preload-pcap --nm-delay=15 --loop=9999999999 --mbps=$BANDWIDTH /home/lab8/pcap/SODIUM_test/${ATTACK_RATE}_${PKT_SIZE}.pcap"
  PROGRAM="tcpreplay"

  FILE=$LOG_PATH/$TEST_ID.$PROGRAM

  run $SERVER $PROGRAM "$APP_PARAM"
  
  #filter output
  #$RATE = Bps,Mbps, pps
  RATE=`grep "\[tcpreplay-1\]{" $FILE.txt | sed "s/\[tcpreplay-1\]{//" | sed "s/}//"`
  #$SIZE = pkt,Byte,time
  SIZE=`grep "\[tcpreplay-0\]{" $FILE.txt | sed "s/\[tcpreplay-0\]{//" | sed "s/}//"`
  #$FLOW = #flows,#flows,?,fps, #flow packet, #non-flows
  FLOW=`grep "\[tcpreplay-2\]{" $FILE.txt | sed "s/\[tcpreplay-2\]{//" | sed "s/}//"`

  REST="$RATE,$SIZE,$FLOW"
  if [[ -z "$REST" ]]; then
    REST=",,,,,,,,,,,"
  fi

  echo $REST> $FILE.txt.tmp
}


echo ""
date
echo ""


echo "Run mmt-security"
run_security 192.168.0.7  1 &
run_security 192.168.0.35 2 &

#wait for mmt-sec starts
sleep 1


#mmt-probe need to terminate before mmt-sec
INTERVAL=$((INTERVAL-10))

echo "Run mmt-probe"
run_probe 192.168.0.7  1 &
run_probe 192.168.0.35 2 &

sleep 5

#mmt-lb will be killed before mmt-probe 10s
INTERVAL=$((INTERVAL-10))

echo "Run mmt-lb"
run_lb 192.168.0.36 &


#only need to sleep 1 second as traffic will generate after 10s by --nm-delay=10
sleep 1

#traffic-gen will be killed before mmt-lb 10s
INTERVAL=$((INTERVAL-10))

echo "Run tcpreplay"
run_traffic_gen 192.168.0.37


#wait for all ssh
FAIL=0
for job in `jobs -p`
do
   wait $job || let "FAIL+=1"
done

TRAF_OUTPUT=$(  cat $LOG_PATH/$TEST_ID.tcpreplay.txt.tmp)
LB_OUTPUT=$(    cat $LOG_PATH/$TEST_ID.lb.txt.tmp)
PROBE1_OUTPUT=$(cat $LOG_PATH/$TEST_ID.probe1.txt.tmp)
PROBE2_OUTPUT=$(cat $LOG_PATH/$TEST_ID.probe2.txt.tmp)
SEC1_OUTPUT=$(  cat $LOG_PATH/$TEST_ID.sec1.txt.tmp)
SEC2_OUTPUT=$(  cat $LOG_PATH/$TEST_ID.sec2.txt.tmp)

rm $LOG_PATH/*.tmp &> /dev/null

#print header of csv file
if [[ $# == 7 ]]; then
  echo "test_id,bandwidth,pkt_size,attack_rate,probe_cores,rules_count,|tcpreplay->,Bps,Mbps,pps,pkt_count,byte_count,duration,flows_count,?,?,fps,flow_pkts,non_flow,|load_balancer->,pkt recv, pkt pros, #drop, %drop, #err,%err,?,?,?,non_http_pkt,http_pkt,|probe1->,id,#pkt_proc,#drop,%drop,#error,#pkt_recv,#reports,|probe->2,id,#pkt_proc,#drop,%drop,#error,#pkt_recv,#reports,|security1->,#alerts,#reports,|security->2,#alerts,#reports" > $OUTPUT 
fi


echo "$CONFIG,|,$TRAF_OUTPUT,|,$LB_OUTPUT,|,$PROBE1_OUTPUT,|,$PROBE2_OUTPUT,|,$SEC1_OUTPUT,|,$SEC2_OUTPUT" >> $OUTPUT

#done
echo ""
date
