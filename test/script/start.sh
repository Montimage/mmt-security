#!/bin/bash

export TZ=Europe/Paris
echo "Sync time of 3 machines"
#sync time
ssh root@192.168.0.7  "export TZ=Europe/Paris && date --set \"$(date)\""
ssh root@192.168.0.35 "export TZ=Europe/Paris && date --set \"$(date)\""
ssh root@192.168.0.36 "export TZ=Europe/Paris && date --set \"$(date)\""

INDEX=0
#print out header
FIRST=0

function run_test() {
  
  INDEX=$((INDEX + 1))

  echo "$INDEX ================= $(date)" | tee -a logs/log.txt
  ./one-test.sh $INDEX $BW $PKT $A_RATE $CORE $RULE $FIRST >> logs/log.txt 2>&1

  #print header of output-file only for the first time
  unset FIRST

  echo "sleep 2s ..."
  sleep 2

}

#rm logs/*

#base
for BW in 8600 8800 9000 9200 9400 9600
do
  CORE=16
  RULE=200
  PKT=800
  A_RATE=10
  
  run_test
done

#pkt
for BW in 6100 6300 6500 6700
do
  CORE=16
  RULE=200
  PKT=600 #
  A_RATE=10
  
  run_test
done

#pkt
for BW in 8100 8300 8500 8700 8900 9100
do
  CORE=16
  RULE=200
  PKT=1000 #
  A_RATE=10
  
  run_test
done

#a_rate
for BW in 8000 8100 8300 8500 8700
do
  CORE=16
  RULE=200
  PKT=800
  A_RATE=20 #
  
  run_test
done
#a_rate
for BW in 6500 6700 6900 7100
do
  CORE=16
  RULE=200
  PKT=800
  A_RATE=40 #
  
  run_test
done


#core
for BW in 5600 5800 6000 6200
do
  CORE=8 #
  RULE=200
  PKT=800
  A_RATE=10
  
  run_test
done

#rule
for BW in 4600 4800 5000 5200
do
  CORE=16
  RULE=400
  PKT=800
  A_RATE=10
  
  run_test
done
