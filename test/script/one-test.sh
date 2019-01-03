#!/bin/bash 

#do statistic in at most 3 minutes
INTERVAL=210

#rate of #noHTTP_rules/#HTTP_rules
#rate = x => there is 1 rule HTTP and x rules noHTTP
HTTP_noHTTP_RULE_RATE=2


if [[ $# != 7 && $# != 8 ]]; then
  echo "usage: $0 test_id bandwidth pkt_size attack_rate probe_core rules_count rule_type [loop]"
  echo "       the last parameter is optional, representing loops count. Ifx=0 we run the test in ~2minutes and print header to output file"
  exit 0
fi

export TZ=Europe/Paris

TEST_ID=$1
BANDWIDTH=$2
PKT_SIZE=$3
ATTACK_RATE=$4
PROBE_CORE=$5
RULES_COUNT=$6
#test type: simple or complex rules
TYPE=$7
#TYPE="simple"



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

case "$TYPE" in
  "simple"|"complex") ;;
  *) echo "rule_type must be \"simple\" or \"complex\"" && exit 1;;
esac


#calculate loops count

case "$ATTACK_RATE-$PKT_SIZE" in
  "normal-600")  LOOP=12000 ;;
  "10-600")      LOOP=300 ;;
  "20-600")      LOOP=600 ;;
  "40-600")      LOOP=1200 ;;

  "normal-800")  LOOP=11000 ;;
  "10-800")      LOOP=45000 ;;
  "20-800")      LOOP=500 ;;
  "40-800")      LOOP=1200 ;;

  "normal-1000") LOOP=11800 ;;
  "10-1000")     LOOP=200 ;;
  "20-1000")     LOOP=400 ;;
  "40-1000")     LOOP=1000 ;;
esac

LOOP=$((LOOP*$BANDWIDTH/20000))


if [[ $8 -ne 0 ]]; then
  LOOP=$8
fi

#path on remote server in which we run the tests
APP_PATH="/opt/mmt/test"

LOG_PATH="logs"

#output of any tests
OUTPUT=$LOG_PATH/output.csv
#output of this test
SINGE_OUTPUT=$LOG_PATH/$TEST_ID.csv

DESCRIPTION="bandwidth $BANDWIDTH, pkt-size $PKT_SIZE, attack rate $ATTACK_RATE, #core $PROBE_CORE, #rules $RULES_COUNT*$((HTTP_noHTTP_RULE_RATE+1)), $TYPE"

#gnuplot
A_RATE=$ATTACK_RATE
if [[ "$A_RATE" == "normal" ]]; then
  A_RATE="0"
fi

GRAPH_TITLE="$(date +%Y-%m-%d\ %H:%M:%S)\nbw $BANDWIDTH Mbps, pkt-size $PKT_SIZE Byte, attack rate $A_RATE%,\n #core $PROBE_CORE, #rules $RULES_COUNT"
START=$(date +%s)
END=$((START+INTERVAL+30))
XRANGE="$START:$END"

date >  $SINGE_OUTPUT
echo "test $TEST_ID, $DESCRIPTION" 

CONFIG="$TEST_ID,$BANDWIDTH,$PKT_SIZE,$ATTACK_RATE,$PROBE_CORE,$RULES_COUNT*$((HTTP_noHTTP_RULE_RATE+1)),$TYPE"


# $1 : IP
# $2 : program
function kill_proc () {
  IP=$1
  PROG=$2

  TIME=10
  case "$PROG" in
    "sec")   TIME=5 ;;
    "lb")    TIME=15 ;;
    "probe") TIME=7 ;;
  esac
  
  echo "kill $PROG"

  ssh $1 "cd $APP_PATH && pkill -INT $PROG && sleep $TIME && pkill -INT $PROG && sleep 3 && pkill -TERM $PROG" &> /dev/null
}

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
# $5 : name
function run () {
  ssh $1 "mkdir -p $APP_PATH/ &> /dev/null"
  #copy run-file
  scp run-proc.sh $1:/$APP_PATH/run$5.sh > /dev/null
  #copy program to server
  scp apps/$2 $1:$APP_PATH/$2   > /dev/null
  #run
  ssh $1 "chmod +x $APP_PATH/run$5.sh &> /dev/null && $APP_PATH/run$5.sh $APP_PATH $2 \"$3\" $INTERVAL $TEST_ID.$2$4"
  #get log
  scp $1:$APP_PATH/$TEST_ID.$2$4* $LOG_PATH/ > /dev/null
  #draw graph
  ./draw.sh $LOG_PATH/$TEST_ID.$2$4.stat $XRANGE "$GRAPH_TITLE" > $LOG_PATH/$TEST_ID.$2$4.png
}


# $1 : IP server
# $2 : id
function run_probe () {
  SERVER="root@$1"
  PROBE_CONF="probe$2_$TYPE.conf"
  APP_PARAM="-c $PROBE_CORE_MASK -- -c $APP_PATH/$PROBE_CONF"
  PROGRAM="probe"

  #update thread_number in probe.conf
  sed -e "s/^thread-nb.*/thread-nb=$PROBE_CORE/" $PROBE_CONF > probe$2_tmp.conf

  scp probe$2_tmp.conf $SERVER:$APP_PATH/$PROBE_CONF > /dev/null

  rm probe$2_tmp.conf

  run $SERVER $PROGRAM "$APP_PARAM" $2 p

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
  #increase rules for nonHTTP
  if [[ $2 -eq 1 ]]; then
    START_INDEX=$((RULES_COUNT*HTTP_noHTTP_RULE_RATE+1))
  fi
  APP_PARAM="-p /opt/mmt/probe/bin/mysocket -c 37-84 -m (0:${START_INDEX}-100000) -n 3 -v"
  PROGRAM="sec"

  #create rules folder if need, remove its old content
  ssh $1 "mkdir -p $APP_PATH/rules &> /dev/null ; rm $APP_PATH/rules/* &> /dev/null"
  scp -r rules/$2.*$TYPE.*.so $SERVER:$APP_PATH/rules/ &> /dev/null

  run $SERVER $PROGRAM "$APP_PARAM" $2 s

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
  LB_OUTPUT=`grep "\[mmt-report-1\]{3," $FILE.txt | sed "s/\[mmt-report-1\]{3,//" | cut -d',' -f1-6` 
  #HTTP pkt, non-HTTP pkt
  HTTP=`grep "\[mmt-report-0\]{" $FILE.txt | sed "s/\[mmt-report-0\]{//" | cut -d',' -f2 ` 
  NO_HTTP=`grep "\[mmt-report-0\]{" $FILE.txt | sed "s/\[mmt-report-0\]{//" | cut -d',' -f3` 

  #if no report => insert empty
  if [[ -z "$LB_OUTPUT" ]]; then
    LB_OUTPUT=",,,,,,,,"
  fi
  echo "$LB_OUTPUT,$NO_HTTP,$HTTP" > $FILE.txt.tmp

}

# $1 : IP server
function run_traffic_gen () {
  SERVER="root@$1"
  APP_PARAM="-i eth2 --unique-ip --netmap --preload-pcap --nm-delay=25 --loop=$LOOP --mbps=$BANDWIDTH /home/lab8/pcap/SODIUM_test/${ATTACK_RATE}_${PKT_SIZE}.pcap"
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
  if [[ -z "$RATE" ]]; then
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

echo "Run mmt-probe"
run_probe 192.168.0.7  1 &
run_probe 192.168.0.35 2 &

sleep 1

#mmt-lb will be killed before mmt-probe 10s
echo "Run mmt-lb"
run_lb 192.168.0.36 &


#only need to sleep 1 second as traffic will generate after 15s by --nm-delay=15
sleep 3

echo "Run tcpreplay"
run_traffic_gen 192.168.0.37

sleep 5

kill_proc 192.168.0.36 lb

sleep 3

kill_proc 192.168.0.7  probe &
kill_proc 192.168.0.35 probe

sleep 15

kill_proc 192.168.0.7  sec & 2> /dev/null
kill_proc 192.168.0.35 sec   2> /dev/null


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
txt="test_id,bandwidth,pkt_size,attack_rate,probe_cores,rules_count,rule_type,|tcpreplay->,loops,Bps,Mbps,pps,pkt_count,byte_count,duration,flows_count,flow_uniq,flow_exp,fps,flow_pkts,non_flow,|load_balancer->,pkt_recv, pkt_proc, #drop, %drop, #err,%err,non_http_pkt,http_pkt,|probe1(nonHTTP)->,id,#pkt_proc,#drop,%drop,#error,#pkt_recv,#reports,|probe2(HTTP)->,id,#pkt_proc,#drop,%drop,#error,#pkt_recv,#reports,|security1(nonHTTP)->,#alerts,#reports,|security2(HTTP)->,#alerts,#reports"

if [[ "$8" == "0" ]]; then
  echo $txt >> $OUTPUT 
fi


txt="$CONFIG,|,$LOOP,$TRAF_OUTPUT,|,$LB_OUTPUT,|,$PROBE1_OUTPUT,|,$PROBE2_OUTPUT,|,$SEC1_OUTPUT,|,$SEC2_OUTPUT"

echo $txt >> $OUTPUT


txt="config\n ,test_id,bandwidth,pkt_size,attack_rate,probe_cores,rules_count,rule_type\n, $CONFIG \n tcpreplay \n ,loops,Bps,Mbps,pps,pkt_count,byte_count,duration,flows_count,flow_uniq,flow_exp,fps,flow_pkts,non_flow \n ,$LOOP,$TRAF_OUTPUT \n load_balancer\n ,#pkt_recv, #pkt_proc, #drop, %drop, #err,%err,#non_http_pkt,#http_pkt \n ,$LB_OUTPUT \n probe1(nonHTTP)\n ,id,#pkt_proc,#drop,%drop,#error,#pkt_recv,#reports\n ,$PROBE1_OUTPUT \n probe2(HTTP) \n ,id,#pkt_proc,#drop,%drop,#error,#pkt_recv,#reports \n ,$PROBE2_OUTPUT \n security1(nonHTTP)\n ,#alerts,#reports\n ,$SEC1_OUTPUT \n security2(HTTP) \n ,#alerts,#reports \n ,$SEC2_OUTPUT"
echo -e $txt >> $SINGE_OUTPUT

date >>  $SINGE_OUTPUT

#done
echo ""
date
