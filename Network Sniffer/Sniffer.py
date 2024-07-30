import scapy.all as scapy
import psutil
from prettytable import PrettyTable
import subprocess
import re
import time
from colorama import Fore, Style
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Function to get the current MAC address of the system.
def get_current_mac(interface):
    try:
        output = subprocess.check_output(["ifconfig", interface])
        return re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(output)).group(0)
    except Exception as e:
        print(f"{Fore.RED}Error getting MAC address: {e}{Style.RESET_ALL}")
        return None

# Function to get the current IP address of the system.
def get_current_ip(interface):
    try:
        output = subprocess.check_output(["ifconfig", interface])
        pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        output1 = output.decode()
        ip = pattern.search(output1)[0]
        return ip
    except Exception as e:
        print(f"{Fore.RED}Error getting IP address: {e}{Style.RESET_ALL}")
        return None

# Function to get IP table of the system.
def ip_table():
    try:
        addrs = psutil.net_if_addrs()
        t = PrettyTable([f"{Fore.GREEN}Interface", "Mac Address", f"IP Address{Style.RESET_ALL}"])
        for k, v in addrs.items():
            mac = get_current_mac(k)
            ip = get_current_ip(k)
            if ip and mac:
                t.add_row([k, mac, ip])
            elif mac:
                t.add_row([k, mac, f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
            elif ip:
                t.add_row([k, f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}", ip])
        print(t)
    except Exception as e:
        print(f"{Fore.RED}Error generating IP table: {e}{Style.RESET_ALL}")

# Packet callback function to process sniffed packets.
def packet_callback(packet):
    packet_details = f"{Fore.CYAN}Packet Details:{Style.RESET_ALL}\n"
    
    if IP in packet:
        packet_details += f"{Fore.GREEN}IP Layer:{Style.RESET_ALL}\n"
        packet_details += (
            f"Source IP: {packet[IP].src} -> Destination IP: {packet[IP].dst}\n"
            f"ID: {packet[IP].id} ; Version: {packet[IP].version} ; Length: {packet[IP].len} ; Flags: {packet[IP].flags}\n"
            f"Protocol: {packet[IP].proto} ; TTL: {packet[IP].ttl} ; Checksum: {packet[IP].chksum}\n"
        )
    
    if TCP in packet:
        packet_details += f"{Fore.YELLOW}TCP Layer:{Style.RESET_ALL}\n"
        packet_details += (
            f"Source Port: {packet[TCP].sport} -> Destination Port: {packet[TCP].dport}\n"
            f"Sequence Number: {packet[TCP].seq} ; Acknowledgment Number: {packet[TCP].ack}\n"
            f"Window: {packet[TCP].window} ; Checksum: {packet[TCP].chksum}\n"
            f"Flags: {packet[TCP].flags} ; Options: {packet[TCP].options}\n"
        )
    
    if UDP in packet:
        packet_details += f"{Fore.YELLOW}UDP Layer:{Style.RESET_ALL}\n"
        packet_details += (
            f"Source Port: {packet[UDP].sport}\n"
            f"Destination Port: {packet[UDP].dport}\n"
        )
    
    if ICMP in packet:
        packet_details += f"{Fore.YELLOW}ICMP Layer:{Style.RESET_ALL}\n"
        packet_details += (
            f"Type: {packet[ICMP].type}\n"
            f"Code: {packet[ICMP].code}\n"
        )
    
    print(packet_details)

# Function to sniff the packets.
def sniff(interface):
    scapy.sniff(iface=interface, prn=packet_callback, store=False)

# Main function to start the packet sniffer.
def main():
    print(f"{Fore.BLUE}Welcome To Packet Sniffer{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[***] Please Start ARP Spoofer Before Using this Module [***]{Style.RESET_ALL}")
    try:
        ip_table()
        interface = input("[*] Please enter the interface name: ").strip()
        
        if not interface:
            print(f"{Fore.RED}No interface provided. Exiting...{Style.RESET_ALL}")
            return
        
        ip = get_current_ip(interface)
        mac = get_current_mac(interface)
        
        if ip and mac:
            print(f"IP Address: {ip}")
            print(f"MAC Address: {mac}")
            print("[*] Sniffing Packets...")
            sniff(interface)
        else:
            print(f"{Fore.RED}Invalid interface or interface details not found. Exiting...{Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}\n[*] Interrupt...{Style.RESET_ALL}")
        time.sleep(3)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Stopping the Sniffer...{Style.RESET_ALL}")
        time.sleep(3)
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
