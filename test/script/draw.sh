#!/bin/bash

DATA=$1
XRANGE=$2
TITLE=$3

#avoid warning
export LANG="en_US.UTF-8"
export LANGUAGE="en_US.UTF-8"
export LC_ALL="en_US.UTF-8"
export TZ=Europe/Paris
#

gnuplot << EOF
reset
set terminal png

set xdata time
set timefmt "%s"
set format x "%Hh:%M"
set xlabel "time"
set xtics 60
set xrange [$XRANGE]

set ylabel "percent"
set yrange [0:105]

set y2label "GB"
set y2range [0:25]
set ytics nomirror
set y2tics

set title "$TITLE"
set key reverse Left outside
set grid

set style data linespoints

plot "$DATA" using 2:4 title "%CPU" with lines, \
  "" using 2:6 title "Memory" with lines axes x1y2, \
#
EOF
