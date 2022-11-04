The program registers 3 hooks:
1. INPUT: This hook handles packets destinated to the fw machine, which the exercise requires to accept.
          Therefore, this hook only prints "*** Packet Accepted ***" and returns NF_ACCEPT.

2. OUPUT: This hook handles packets sent by the fw machine, which the exercise requires to accept.
          Therefore, this hook only prints "*** Packet Accepted ***" and returns NF_ACCEPT.

3. FORWARD: This hook handles packet that forwarded by the fw machine, which the exercise requires to drop.
          Therefore, this hook only prints "*** Packet Dropped ***" and returns NF_DROP.

In addition, program creates a character device at /dev/hw2secws_char_device, a sysfs class hw2secws_class, a sysfs device hw2secws_class_hw2secws_char_device and file attributes stats_accepted_dropped.
The final file path:
/sys/class/hw2secws_class/hw2secws_class_hw2secws_char_device/stats_accepted_dropped

When printing the file, we will get the format:
$ACCEPTED,$DROPPED
Aka number of accepted packets and number of dropped packets, separated by a comma.

When writing "0" to the file (or any string that starts with '0'), the counters will be zerod to "0,0".

The attached user program is a bash script with cats the file and prints accepted/dropped packets, and total packets.
