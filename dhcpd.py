#python dhcp server 

import scapy.all as scapy
import socket

# DHCP server configuration options
DHCP_SERVER_IP = "192.168.0.2"
DHCP_SERVER_NETMASK = "255.255.255.0"
DHCP_SERVER_ROUTER = "192.168.0.1"
DHCP_SERVER_DNS = "0.0.0.0"
DHCP_SERVER_DOMAIN = "localdomain"
DHCP_SERVER_LEASETIME = 172800
DHCP_SERVER_DHCPDISCOVER = 1
DHCP_SERVER_DHCPOFFER = 2
DHCP_SERVER_DHCPREQUEST = 3
DHCP_SERVER_DHCPACK = 5
DHCP_SERVER_DHCPNAK = 6
DHCP_SERVER_DHCPRELEASE = 7
DHCP_SERVER_DHCPINFORM = 8
DHCP_SERVER_BROADCAST = "ff:ff:ff:ff:ff:ff"
DHCP_SERVER_MAC = "00:00:00:00:00:00"

# send broadcast messages
scapy.conf.checkIPaddr = False

# dhcp discover
def dhcp_discover(packet):
    print("DHCP discover")
    dhcp_discover = scapy.Ether(src=packet[scapy.Ether].dst, dst=packet[scapy.Ether].src)/\
                 scapy.IP(src=DHCP_SERVER_IP, dst="192.168.0.1")/\
                    scapy.UDP(sport=67, dport=68)/\
                        scapy.BOOTP(op=1, chaddr=packet[scapy.Ether].src, xid=packet[scapy.BOOTP].xid)/\
                            scapy.DHCP(options=[("message-type", "discover"), ("param_req_list", 0), ("end")])
    scapy.sendp(dhcp_discover, iface="eth0")

# send dhcp offer
def dhcp_offer(packet):
    print("DHCP offer")
    dhcp_offer = scapy.Ether(src=packet[scapy.Ether].dst, dst=packet[scapy.Ether].src)/\
                 scapy.IP(src=DHCP_SERVER_IP, dst="192.168.0.1")/\
                    scapy.UDP(sport=67, dport=68)/\
                        scapy.BOOTP(op=2, yiaddr="192.168.0.2", siaddr=DHCP_SERVER_IP, giaddr="192.168.0.3", chaddr=packet[scapy.Ether].src, xid=packet[scapy.BOOTP].xid)/\
                            scapy.DHCP(options=[("message-type", "offer"), ("subnet_mask", DHCP_SERVER_NETMASK), ("router", DHCP_SERVER_ROUTER), ("name_server", DHCP_SERVER_DNS), ("domain", DHCP_SERVER_DOMAIN), ("lease_time", DHCP_SERVER_LEASETIME), ("server_id", DHCP_SERVER_IP), "end"])
    scapy.sendp(dhcp_offer, iface="eth0")

# dhcp request
def dhcp_request(packet):
    print("DHCP request")
    dhcp_request = scapy.Ether(src=packet[scapy.Ether].dst, dst=packet[scapy.Ether].src)/\
                 scapy.IP(src=DHCP_SERVER_IP, dst="192.168.0.1")/\
                    scapy.UDP(sport=67, dport=68)/\
                        scapy.BOOTP(op=2, yiaddr="192.168.0.2", siaddr=DHCP_SERVER_IP, giaddr="192.168.0.3", chaddr=packet[scapy.Ether].src, xid=packet[scapy.BOOTP].xid)/\
                            scapy.DHCP(options=[("message-type", "request"), ("subnet_mask", DHCP_SERVER_NETMASK), ("router", DHCP_SERVER_ROUTER), ("name_server", DHCP_SERVER_DNS), ("domain", DHCP_SERVER_DOMAIN), ("lease_time", DHCP_SERVER_LEASETIME), ("server_id", DHCP_SERVER_IP), "end"])
    scapy.sendp(dhcp_request, iface="eth0")

# send dhcp ack
def dhcp_ack(packet):
    print("DHCP ack")
    dhcp_ack = scapy.Ether(src=packet[scapy.Ether].dst, dst=packet[scapy.Ether].src)/\
                 scapy.IP(src=DHCP_SERVER_IP, dst="192.168.0.1")/\
                    scapy.UDP(sport=67, dport=68)/\
                        scapy.BOOTP(op=2, yiaddr="192.168.0.2", siaddr=DHCP_SERVER_IP, giaddr="192.168.0.3", chaddr=packet[scapy.Ether].src, xid=packet[scapy.BOOTP].xid)/\
                            scapy.DHCP(options=[("message-type", "ack"), ("subnet_mask", DHCP_SERVER_NETMASK), ("router", DHCP_SERVER_ROUTER), ("name_server", DHCP_SERVER_DNS), ("domain", DHCP_SERVER_DOMAIN), ("lease_time", DHCP_SERVER_LEASETIME), ("server_id", DHCP_SERVER_IP), "end"])
    scapy.sendp(dhcp_ack, iface="eth0")

# listen for dhcp packets and see if they are dhcp discover packets
def listen():
    print("Listening for DHCP discover packets...")
    scapy.sniff(prn=handle_dhcp_packet, filter="udp and (port 67 or 68)", iface="eth0")

# handle dhcp packets
def handle_dhcp_packet(packet):
    if scapy.DHCP in packet and packet[scapy.DHCP].options[0][1] == DHCP_SERVER_DHCPDISCOVER:
        dhcp_discover(packet)
    elif scapy.DHCP in packet and packet[scapy.DHCP].options[0][1] == DHCP_SERVER_DHCPREQUEST:
        dhcp_request(packet)
    elif scapy.DHCP in packet and packet[scapy.DHCP].options[0][1] == DHCP_SERVER_DHCPACK:
        dhcp_ack(packet)

