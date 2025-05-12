#!/usr/bin/env python3
"""
Script to generate a list of IP addresses and update the devices file.
Generates IPs from 10.100.0.101 to 10.100.0.157.
"""

import ipaddress

# Define the start and end IP addresses
start_ip = ipaddress.IPv4Address('10.100.0.101')
end_ip = ipaddress.IPv4Address('10.100.0.157')

# Generate the list of IP addresses
ip_list = []
current_ip = start_ip
while current_ip <= end_ip:
    ip_list.append(str(current_ip))
    current_ip += 1

# Write the IP addresses to the devices file
with open('devices', 'w') as f:
    for ip in ip_list:
        f.write(f"{ip}\n")

print(f"Updated devices file with {len(ip_list)} IP addresses from {start_ip} to {end_ip}")

