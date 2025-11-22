import scapy.all as scapy

print("IP Address" + "\t" + "MAC Address")

def net_scan(ip):

    live_hosts = []
    #scapy.ls(scapy.ARP())

    arp_request =scapy.ARP(pdst=ip)

    broadcast_ether = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")

    combined_packet = broadcast_ether / arp_request

    
    answered , unanswered = scapy.srp(combined_packet,timeout=1)

    

    for element in answered: # element -> (request,response)   

        live_hosts.append(element[1].psrc)

        print(element[1].psrc,element[1].hwsrc)

    return live_hosts



def port_scan(target_list):

    
    

    ports_string = input("Enter port range: (e.g, 80-2000): ")

    try:
        start_port , end_port = map(int, ports_string.split("-"))

        ports_to_scan = range (start_port, end_port + 1)

    except ValueError:
        print("Error: Invalid port range format. Scanning default ports 80,443,22,25")
        ports_to_scan = [80,443,22,25]
    
    ports_list = ports_string.split("-")

    for ip_address in target_list:
        print(f"\nScanning Host: {ip_address} ")

   
        for port_num in ports_to_scan:
            ip_layer= scapy.IP(dst=ip_address)
            tcp_layer = scapy.TCP(dport=port_num, flags ="S")
            packet = ip_layer / tcp_layer
            response = scapy.sr1(packet, timeout=1,verbose=0)
        
            print(f"Checking Port {port_num}")
            if response is None:
                print(f"Port {port_num}:  Filtered (No Response)")

            elif response.haslayer(scapy.TCP) and response[scapy.TCP].flags == "SA":
                print(f"Port {port_num}:  Open!")

            elif response.haslayer(scapy.TCP) and response[scapy.TCP].flags == "R":
                # Checks for the Closed (RST) flag
                print(f"Port {port_num}:  Closed ")
            else:
                print(f"Port {port_num}: Unknown Response ")


live_hosts=net_scan("192.168.1.1/24")

port_scan(live_hosts)

