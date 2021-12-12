#!/bin/bash

# Just connects to the ports mentioned in PORTS_FILE and save their respective output to a LOG_FILE

IP=10.10.34.51
PORTS_FILE=ports/port_range
LOG_FILE=connection_log

rm $LOG_FILE
for f in $(cat $PORTS_FILE)
do
	echo "CONNECTING TO PORT:" $f
	response=$(ssh alice@$IP -p$f)
	echo "$f: $response" >> $LOG_FILE

done

echo "OUTPUT FILE WRITTEN TO:" $LOG_FILE
