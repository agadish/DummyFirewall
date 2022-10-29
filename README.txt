The program registers 3 hooks:
1. INPUT: This hook handles packets destinated to the fw machine, which the exercise requires to accept.
          Therefore, this hook only prints "*** Packet Accepted ***" and returns NF_ACCEPT.

2. OUPUT: This hook handles packets sent by the fw machine, which the exercise requires to accept.
          Therefore, this hook only prints "*** Packet Accepted ***" and returns NF_ACCEPT.

3. FORWARD: This hook handles packet that forwarded by the fw machine, which the exercise requires to drop.
          Therefore, this hook only prints "*** Packet Dropped ***" and returns NF_DROP.

