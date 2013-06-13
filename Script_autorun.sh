#!/bin/bash

if [ $# -le 1 ]; then
    echo "Usage: sh Script_autorun.sh [run mult] [stop mult]"
else
    echo "Getting bootstrap file..."
    bash get_bootstrap_contacts.sh
    echo "Starting loop..."
    first=1
    client=$RANDOM$RANDOM$RANDOM
    while [ 1 ]
    do
	rdm=$(($RANDOM%400+200))
	run_time=$(($rdm*$1))
	stop_time=$(($rdm*$2))
	echo "Launching client '$client' for $run_time secondes"
	if [ $first -eq 1 ]; then
	    first=0
	    timeout --foreground -s USR1 ${run_time} ./jelly --create=$client --init_storage=2
	else
	    timeout --foreground -s USR1 ${run_time} ./jelly --login=$client
	fi
	echo "Stopping client '$client' for $stop_time secondes"
	sleep $stop_time
    done
fi