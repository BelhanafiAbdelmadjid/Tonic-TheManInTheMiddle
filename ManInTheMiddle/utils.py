import re
import socket
import psutil
from uuid import getnode as get_mac
import ipaddress
import netifaces


def is_valid_ip(ip):
    # Regular expression for a valid IPv4 address
    pattern = r'^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    
    # Check if the IP matches the pattern
    if re.match(pattern, ip):
        # Check if each octet is in the range of 0-255
        return all(0 <= int(octet) <= 255 for octet in ip.split('.'))
    return False

def get_network_config():
    # # Get the local machine name
    # host_name = socket.gethostname()
    # # Get the IP address associated with the local machine name
    # ip_address = socket.gethostbyname(host_name)
    ip_address = socket.gethostbyname_ex(socket.gethostname())[-1][-1]

    mac_int = get_mac()
    mac  = ':'.join(['{:02x}'.format((mac_int >> (i * 8)) & 0xff) for i in range(5, -1, -1)])

    return ip_address , mac
    

def is_ip_in_same_network(ip_to_check):
    ip, mac = get_network_config()
    mask = get_network_mask(ip)
    print("mask",mask)
    # Create network object using network_ip and subnet_mask (subnet mask can be represented as prefix length)
    network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    
    # Create an IP object for the IP to check
    ip = ipaddress.IPv4Address(ip_to_check)
    
    # Check if the IP is in the network
    return ip in network

def im_i_target(ip_target):
    ip, mac = get_network_config()
    return True if ip == ip_target else False

def get_network_mask(ip_address):
    # Get all network interfaces
    interfaces = netifaces.interfaces()

    # Loop through interfaces to find the one with the matching IP address
    for interface in interfaces:
        addrs = netifaces.ifaddresses(interface)

        # Check if the interface has an IPv4 address (AF_INET)
        if netifaces.AF_INET in addrs:
            # Loop through the IPv4 addresses
            for addr in addrs[netifaces.AF_INET]:
                # If the IP matches, return the network mask
                if addr['addr'] == ip_address:
                    return addr['netmask']

    return None  # If no match is found

if __name__ == '__main__':
    print(is_ip_in_same_network("192.168.5.1"))


import threading
class ExceptionThread(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.exception = None

    def run(self):
        try:
            if self._target:
                self._target(*self._args, **self._kwargs)
        except Exception as e:
            self.exception = e
    