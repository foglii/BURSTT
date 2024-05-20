
#!/bin/bash
while true; do

    duration=$((RANDOM % 10 + 1))  # Random duration between 1 and 10 seconds
    sleep_time=$((RANDOM % 5 + 5))   # Random sleep time between 5 and 10 seconds
    total_sleep=$((sleep_time + duration))
    echo "#####################################################################################################"
    echo "Sending TCP traffic for $duration seconds. Next transmission in $total_sleep seconds..."
    echo "#####################################################################################################"
    iperf -c $1 -t $duration -w 1000
    sleep $sleep_time

done
