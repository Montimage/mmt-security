#!/bin/bash

export TZ=Europe/Paris
echo "Sync time of 3 machines"
#sync time
ssh root@192.168.0.7  "export TZ=Europe/Paris && date --set \"$(date)\""
ssh root@192.168.0.35 "export TZ=Europe/Paris && date --set \"$(date)\""
ssh root@192.168.0.36 "export TZ=Europe/Paris && date --set \"$(date)\""

TYPE="complex"
#TYPE="simple"

INDEX=1
#print out header
FIRST=0

function run_test() {
  
  INDEX=$((INDEX + 1))

  echo "$INDEX ================= $(date)" | tee -a logs/log.txt
  ./one-test.sh $INDEX $BW $PKT $A_RATE $CORE $RULE $TYPE $FIRST >> logs/log.txt 2>&1

  #print header of output-file only for the first time
  unset FIRST

  echo "sleep 2s ..."
  sleep 2

}


function test_one_loop() {
  FIRST=1
  BW=3000
  run_test
  unset FIRST
}

#rm logs/*

for test_loop in 1 2 3
do

#base
for BW in $(seq 8900 200 9900)
do
  CORE=16
  RULE=400
  PKT=800
  A_RATE=10
  
  run_test
done

test_one_loop

#pkt
for BW in $(seq 7900 200 8900);
do
  CORE=16
  RULE=400
  PKT=600 #
  A_RATE=10
  
  run_test
done


test_one_loop

#pkt
for BW in $(seq 5900 200 6900);
do
  CORE=16
  RULE=400
  PKT=1000 #
  A_RATE=10
  
  run_test
done


test_one_loop

#a_rate
for BW in $(seq 8500 200 9900);
do
  CORE=16
  RULE=400
  PKT=800
  A_RATE=20 #
  
  run_test
done


test_one_loop

#a_rate
for BW in $(seq 8500 200 9900);
do
  CORE=16
  RULE=400
  PKT=800
  A_RATE=40 #
  
  run_test
done


test_one_loop


#core
for BW in $(seq 3900 200 5900);
do
  CORE=8 #
  RULE=400
  PKT=800
  A_RATE=10
  
  run_test
done



test_one_loop

#rule
#for BW in $(seq 6900 200 7500)
#do
#  CORE=16
#  RULE=400
#  PKT=800
#  A_RATE=10
#  
#  run_test
#done


#test_one_loop

echo "$INDEX,test_loop,$test_loop" >> logs/output.csv

done
