#!/bin/bash

export TZ=Europe/Paris
CPUS_COUNT=$(nproc --all)

function print_ts () {
  TIMESTAMP="$(date +%s)"
  echo -e "ts ${TIMESTAMP} $2" >> $1
}

# $1: index
# $2: proc name
# $3: output file
function stat () {
  CPU=$(ps -C "$2" -o "%cpu" | tail -n +2 | xargs  | sed -e 's/\ /+/g' | bc)
  if [ -z "$CPU" ]; then
    CPU=0
    MEM=0
    VSIZE=0
  else
    MEM=$(ps -C "$2" -o "%mem" | tail -n +2 | xargs  | sed -e 's/\ /+/g' | bc)
    VSIZE=$(ps -C "$2" -o "vsize" | tail -n +2 | xargs  | sed -e 's/\ /+/g' | bc)
    VSIZE=$(echo "scale=2; $VSIZE/1000/1000" | bc)
  fi

  CPU=$(echo "scale=2; $CPU/$CPUS_COUNT"   | bc)

  print_ts $3 "$1 $CPU $MEM $VSIZE $CMD"
}

# $1 : proc_name
# $2 : interval (in second)
# $3 : output
function stat_proc () {
  #empty file 
  echo > $3 
  for (( i=0; i < $2; ++i ))
  do
    stat $i $1 $3
    sleep 1
  done

   stat $i $1 $3
}

# $1 : directory
# $2 : program name
# $3 : parameters
# $4 : interval (in second)
# $5 : output
cd $1

PROGRAM=$2

#kill $1 if it is running
pkill -TERM $PROGRAM &> /dev/null 

#empty output file
date > "$5.txt"

#background process to do statistic
stat_proc "$PROGRAM" "$4" "$5.stat" &

print_ts "$5.txt" "(start $PROGRAM $3)"

#run the program
./$PROGRAM $3 >> "$5.txt" 2>&1 

sleep 1

print_ts "$5.txt" "(end $PROGRAM)"

echo "finish $PROGRAM"

date >> "$5.txt"

#stop statistic
kill -TERM $!

exit 0
