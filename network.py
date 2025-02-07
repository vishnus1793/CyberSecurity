import scapy.all as sc
import requests
from tabulate import tabulate

def scan(ip_range):
    print("[+] Scanning network, please wait...")
    arp_request = sc.ARP(pdst=ip_range)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = sc.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    clients = []

    for answer in answered_list:
        clients.append({"IP Address": answer[1].psrc, "MAC Address": answer[1].hwsrc})

    return clients

def get_mac_vendor(mac_address):
    try:
        url = f"https://api.macvendors.com/{mac_address}"
        response = requests.get(url, timeout=2)
        return response.text if response.status_code == 200 else "Unknown Vendor"
    except requests.exceptions.RequestException:
        return "API Error"

def print_result(clients):
    if clients:
        print("\n[+] Scan Complete! Devices found:")
        print(tabulate(clients, headers="keys", tablefmt="grid"))
    else:
        print("\n[-] No Devices found on the network.")

network_range = "192.168.227.0/24"
clients_list = scan(network_range)

for client in clients_list:
    client["Vendor"] = get_mac_vendor(client["MAC Address"])

print_result(clients_list)
