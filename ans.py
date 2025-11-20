import scapy.all as scapy

print("IP Address" + "\t" + "MAC Address")

def net_scan(ip):
    #scapy.ls(scapy.ARP())

    arp_request =scapy.ARP(pdst=ip)

    broadcast_ether = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")

    combined_packet = broadcast_ether / arp_request

    answered , unanswered = scapy.srp(combined_packet,timeout=1)

    for element in answered: # element -> (request,response)   
        print(element[1].psrc,element[1].hwsrc)

net_scan("192.168.1.1/24")