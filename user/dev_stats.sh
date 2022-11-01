#!/bin/sh

# Configuration
CLASS_NAME="hw2secws"
DEVICE_NAME="hw2secws_class_hw2secws_class_char_device"
FILE_NAME="stats_accepted_dropped"
FILE_PATH=/sys/class/$CLASS_NAME/$DEVICE_NAME/$FILE_NAME

# 1. Read file
IFS=, cat $FILE_PATH | read -r accepted_packets dropped_packets

# 2. Print stats
echo "Firewall Packets Summary:"
echo "Number of accepted packets: $accepted_packets"
echo "Number of dropped packets: $dropped_packets"
echo "Total number of packets: $(($accepted_packets + $dropped_packets))"

