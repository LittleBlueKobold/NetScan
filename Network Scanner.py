from scapy.all import ARP, Ether, srp  #import scapy libraries

def scan_network(ip_range):  #Define scanning network function
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") #provide mac of found ip
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    for element in answered_list:
        print(f"IP: {element[1].psrc}, MAC: {element[1].hwsrc}")
        #print out of devices found on requested network, including IP and MAC

scan_network("192.168.1.0/24")