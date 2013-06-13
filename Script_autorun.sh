#!/bin/bash

if [ $# -le 1 ]; then
    echo "Usage: sh Script_autorun.sh [run mult] [stop mult]"
else
    echo "Getting bootstrap file..."
    chmod 700 mailtorkey.pem
    scp -i mailtorkey.pem ubuntu@ec2-50-17-89-139.compute-1.amazonaws.com:/home/ubuntu/p2pstorage/bootstrap_contacts .


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
	    ./jelly --create=$client --init_storage=2 &
	    first=0
	else
	    ./jelly --login=$client &
	fi
	PID=$!
	sleep $run_time
	echo "Stopping client '$client' for $stop_time secondes"
	kill -USR1 $PID
	sleep $stop_time
    done
fi