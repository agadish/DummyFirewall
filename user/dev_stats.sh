#!/bin/bash

# Configuration
CLASS_NAME="hw2secws_class"
DEVICE_NAME="hw2secws_class_hw2secws_char_device"
FILE_NAME="stats_accepted_dropped"
FILE_PATH=/sys/class/$CLASS_NAME/$DEVICE_NAME/$FILE_NAME

# 1. Read file
IFS="," read -r accepted_packets dropped_packets <<< $(cat $FILE_PATH)

# 2. Print stats
echo "Firewall Packets Summary:"
echo "Number of accepted packets: $accepted_packets"
echo "Number of dropped packets: $dropped_packets"
echo "Total number of packets: $(($accepted_packets + $dropped_packets))"

