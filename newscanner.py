import nmap
import tkinter as tk
from tkinter import ttk

def scan_network(target_ip):
    nm = nmap.PortScanner()

    # Perform a ping scan to discover live hosts in the network
    nm.scan(hosts=target_ip, arguments='-sn')

    # Iterate through each discovered host
    for host in nm.all_hosts():
        result_text.insert(tk.END, f"\nHost: {host}\n")

        # Perform a detailed scan on each live host, including OS detection and service/version detection
        nm.scan(hosts=host, arguments='-sS -O -sV ')

        # Extract information about open ports
        open_ports = [port for port in nm[host]['tcp'] if nm[host]['tcp'][port]['state'] == 'open']
        result_text.insert(tk.END, f"Open Ports: {open_ports}\n")

        # Extract information about services on open ports, including version
        for port in open_ports:
            service = nm[host]['tcp'][port]['name']
            version = nm[host]['tcp'][port].get('product', 'N/A')
            result_text.insert(tk.END, f"Port {port}: {service} ({version})\n")

        # Extract MAC address (if available)
        mac_address = nm[host]['addresses'].get('mac', 'N/A')
        result_text.insert(tk.END, f"MAC Address: {mac_address}\n")

        # Extract hostname (if available)
        hostname = nm[host].hostname()
        result_text.insert(tk.END, f"Hostname: {hostname}\n")

        # Extract OS information
        os_info = nm[host]['osmatch'][0]['name'] if 'osmatch' in nm[host] else 'N/A'
        result_text.insert(tk.END, f"OS: {os_info}\n\n")

def start_scan():
    target_ip = entry_target_ip.get()
    result_text.delete(1.0, tk.END)  # Clear previous results
    scan_network(target_ip)

# Create main window
root = tk.Tk()
root.title("Network Scanner GUI")

# Create and place widgets
label_target_ip = ttk.Label(root, text="Enter the target IP address or range:")
label_target_ip.pack(pady=10)

entry_target_ip = ttk.Entry(root, width=30)
entry_target_ip.pack(pady=10)

button_scan = ttk.Button(root, text="Scan Network", command=start_scan)
button_scan.pack(pady=10)

result_text = tk.Text(root, height=20, width=70)
result_text.pack(pady=10)

# Start the main loop
root.mainloop()
