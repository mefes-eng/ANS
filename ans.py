import scapy.all as scapy

def get_os(ttl):
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Unknown / Cisco , Network Device"

def net_scan(ip):
    live_hosts = []
    print(f"Scanning Network {ip}...")
    arp_request = scapy.ARP(pdst=ip)
    broadcast_ether = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")
    combined_packet = broadcast_ether / arp_request
    
    answered, unanswered = scapy.srp(combined_packet, timeout=1, verbose=0)

    print("IP Address" + "\t\t" + "MAC Address")
    print("-" * 40)

    for element in answered: 
        live_hosts.append(element[1].psrc)
        print(f"{element[1].psrc}\t\t{element[1].hwsrc}")

    return live_hosts

def port_scan(target_list):
    ports_string = input("Enter port range: (e.g, 80-2000): ")

    try:
        start_port , end_port = map(int, ports_string.split("-"))
        ports_to_scan = range (start_port, end_port + 1)
    except ValueError:
        print("Error: Invalid port range format. Scanning default ports 80,443,22,25")
        ports_to_scan = [80,443,22,25]
    
    for ip_address in target_list:
        print(f"\nScanning Host: {ip_address} ")

        packet_list = []
        
        detected_os = None

        for port_num in ports_to_scan:
            ip_layer= scapy.IP(dst=ip_address)
            tcp_layer = scapy.TCP(dport=port_num, flags ="S")
            packet_list.append(ip_layer / tcp_layer)

        answered , unanswered = scapy.sr(packet_list, timeout=2, verbose=0)

        for sent_packet, received_packet in answered:
            
            if detected_os is None and received_packet.haslayer(scapy.IP):
                    ttl_value = received_packet[scapy.IP].ttl
                    detected_os = get_os(ttl_value)
                    print(f"👉 Operating System Guess: {detected_os} (TTL: {ttl_value})")
            
            if received_packet.haslayer(scapy.TCP) and received_packet[scapy.TCP].flags == "SA":
                port = received_packet[scapy.TCP].sport
                print(f" Port {port}: OPEN!")

    
live_hosts = net_scan("192.168.1.1/24")

if live_hosts:
    port_scan(live_hosts)
else:
    print("No live hosts found on the network.")