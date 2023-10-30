#!/bin/bash 

# File containing a list of server IP addresses
ip_list="ip_list.txt"

# Test where a user can RDP
while read ip_address; do 
	hydra -t 1 -W 1 -l 'your_username' -p 'your_password' rdp://$ip_address
done < "$ip_list"
