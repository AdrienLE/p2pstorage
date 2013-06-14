#!/bin/bash

if [ $# -le 1 ]; then
    echo "Usage: sh Script_autorun.sh [run mult] [stop mult]"
else
    echo "Getting bootstrap file..."
    bash get_bootstrap_contacts.sh
    echo "Starting loop..."
    first=1
    client=$RANDOM$RANDOM$RANDOM
    T=600

    t_run=0
    t_stop=0
    t_dec=8

    delay=$(($RANDOM%($T/5)))
    echo "Starting delay is $delay, waiting..."
    sleep $delay

    while [ 1 ]
    do
	rdm=$(($RANDOM%($T/($t_dec/2))-($T/$t_dec)))
	run_time=$((($T*$1)/($1 + $2)+$rdm))
	stop_time=$((($T*$2)/($1 + $2)-$rdm))
	t_run=$(($t_run+$run_time))
	t_stop=$(($t_stop+$stop_time))
	echo "[AUTORUN] Running client '$client' for $run_time secondes"
	if [ $first -eq 1 ]; then
	    first=0
	    timeout --foreground -s USR1 ${run_time} ./jelly --create=$client --init_storage=2
	else
	    timeout --foreground -s USR1 ${run_time} ./jelly --login=$client
	fi
	echo "[AUTORUN] Stopping client '$client' for $stop_time secondes"
	sleep $stop_time
    done
fi