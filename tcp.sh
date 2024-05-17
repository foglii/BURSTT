
#!/bin/bash
while true; do
    duration=$((RANDOM % 10 + 1))  # Random duration between 1 and 10 seconds
    sleep_time=$((RANDOM % 5 + 5))   # Random sleep time between 5 and 10 seconds
    total_sleep=$((sleep_time + duration))
    echo "Sending TCP traffic for $duration seconds. Next transmission in $total_sleep seconds..."
    echo "Sending TCP traffic for $duration seconds. Next transmission in $total_sleep seconds..." > output.txt
    #h1=$(hostname -I | awk '{print $1}')
    #h2=$(hostname -I | awk '{print $2}')
    #h1_ip=$(h1 ifconfig h1-eth0 inet )
    iperf -c 10.0.0.1 -t $duration
    sleep $total_sleep

done
