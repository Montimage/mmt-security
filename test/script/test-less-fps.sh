#!/bin/bash

export TZ=Europe/Paris
echo "Sync time of 3 machines"
#sync time
ssh root@192.168.0.7  "export TZ=Europe/Paris && date --set \"$(date)\""
ssh root@192.168.0.35 "export TZ=Europe/Paris && date --set \"$(date)\""
ssh root@192.168.0.36 "export TZ=Europe/Paris && date --set \"$(date)\""

INDEX=100
#print out header
FIRST=0
TYPE="complex"

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

cp logs/output.csv logs/output_$(date).csv
#test 91kfps
cp /home/lab8/pcap/SODIUM_test/10_800_91kfps.pcap /home/lab8/pcap/SODIUM_test/10_800.pcap

for file in 1 2
do
	for test_loop in 1 2
	do

		#base
		for BW in 9300 9400 9500 9600 10000
		do
		  CORE=16
		  RULE=400
		  PKT=800
		  A_RATE=10
		  
		  run_test
		done

		#pkt
		echo "$INDEX,test_loop,$test_loop" >> logs/output.csv

	done

	test_one_loop

	#test second file
	cp /home/lab8/pcap/SODIUM_test/10_800_116kfps.pcap /home/lab8/pcap/SODIUM_test/10_800.pcap
	echo "file 116kfps" >> logs/output.csv
done


FIRST=200000
