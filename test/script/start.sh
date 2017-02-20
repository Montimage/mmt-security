#!/bin/bash

export TZ=Europe/Paris
#sync time
ssh root@192.168.0.7  "export TZ=Europe/Paris && date --set \"$(date)\""
ssh root@192.168.0.35 "export TZ=Europe/Paris && date --set \"$(date)\""
ssh root@192.168.0.36 "export TZ=Europe/Paris && date --set \"$(date)\""

INDEX=0
#print out header
FIRST=2

#rm logs/*

#number of cores for probe
for CORE in 16 8
do
  #number of rules for security
  for RULE in 100 200 400
  do
    #bandwidth
    for BW in 5000 7000 9500
    do
      #packet size
      for PKT in 600 800 1000
      do
        #attack rate
        for A_RATE in normal 10 20 40
        do
     
          INDEX=$((INDEX + 1))

            echo "$INDEX ================= $(date)" | tee -a logs/log.txt
            ./one-test.sh $INDEX $BW $PKT $A_RATE $CORE $RULE $FIRST >> logs/log.txt 2>&1

            #print header of output-file only for the first time
            unset FIRST
            
            echo "sleep 2s ..."
            sleep 2

        done
      done
    done
  done
done
