import re
import socket
import psutil
from uuid import getnode as get_mac
import ipaddress
import netifaces
import threading

import platform
import psutil
import socket
import os


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

    mac = get_mac_address(ip_address)
    # mac  = ':'.join(['{:02x}'.format((mac_int >> (i * 8)) & 0xff) for i in range(5, -1, -1)])

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

def get_mac_address(ip_address):
    # Get all network interfaces
    interfaces = netifaces.interfaces()

    # Loop through interfaces to find the one with the matching IP address
    for interface in interfaces:
        addrs = netifaces.ifaddresses(interface)

        # Check if the interface has an IPv4 address (AF_INET)
        if netifaces.AF_INET in addrs:
            # Loop through the IPv4 addresses
            for addr in addrs[netifaces.AF_INET]:
                # If the IP matches, get the MAC address of the interface
                if addr['addr'] == ip_address:
                    # Check if the interface has a MAC address (AF_LINK)
                    if netifaces.AF_LINK in addrs:
                        # Return the MAC address
                        return addrs[netifaces.AF_LINK][0]['addr']
    return None




def get_system_info():
     # Fonction spécifique pour récupérer les périphériques
    def get_all_devices():
        devices = []
        if platform.system() == "Windows":
            try:
                import wmi
                c = wmi.WMI()

                # Récupère les périphériques USB
                for usb in c.Win32_USBControllerDevice():
                    devices.append(usb.Dependent.Caption)

                # Récupère les périphériques audio
                for audio in c.Win32_SoundDevice():
                    devices.append(audio.Caption)

                # Récupère les périphériques d'entrée
                for input_device in c.Win32_Keyboard():
                    devices.append(input_device.Caption)
                for input_device in c.Win32_PointingDevice():
                    devices.append(input_device.Caption)

            except ImportError:
                print("WMI module not installed. Device details may be incomplete.")
        else:
            # Sur Linux, on peut utiliser `lsusb` pour récupérer des périphériques USB
            if os.path.exists("/usr/bin/lsusb"):
                try:
                    with os.popen("lsusb") as f:
                        for line in f:
                            devices.append(line.strip())
                except Exception as e:
                    print(f"Error fetching devices: {e}")
            else:
                devices.append("lsusb command not available.")

        # Affiche la liste de tous les périphériques trouvés
        for device in devices:
            print(device)
    info = {}

    # Système d'exploitation
    info["OS"] = platform.system()
    info["OS Version"] = platform.version()
    info["OS Release"] = platform.release()

    # Processeur
    info["Physical Cores"] = psutil.cpu_count(logical=False)
    info["Total Cores"] = psutil.cpu_count(logical=True)
    info["Processor"] = platform.processor()

    # RAM
    ram = psutil.virtual_memory()
    info["Total RAM"] = f"{ram.total / (1024 ** 3):.2f} GB"

    # Batterie (si disponible)
    if psutil.sensors_battery():
        battery = psutil.sensors_battery()
        info["Battery Percentage"] = f"{battery.percent}%"
        info["Power Plugged"] = battery.power_plugged
    else:
        info["Battery"] = "No battery detected"

    # Périphériques connectés
    devices = []
    for device in psutil.disk_partitions():
        devices.append({
            "Device": device.device,
            "Mount Point": device.mountpoint,
            "File System Type": device.fstype
        })
    info["Connected Devices"] = devices

    # # Affichage des informations
    # for key, value in info.items():
    #     print(f"{key}: {value}")
    # get_all_devices()

    def format_system_info(info):
        """Format system information dictionary into a human-readable string."""
        formatted = []
        
        def add_line(key, value, indent=0):
            """Helper function to add a line with proper indentation."""
            formatted.append(f"{' ' * indent}{key}: {value}")
        
        for key, value in info.items():
            if isinstance(value, list):  # Handle lists
                add_line(key, "", indent=0)
                for i, item in enumerate(value):
                    add_line(f"  - Device {i + 1}", "", indent=2)
                    if isinstance(item, dict):  # Handle nested dictionaries
                        for sub_key, sub_value in item.items():
                            add_line(f"{sub_key}", sub_value, indent=4)
                    else:
                        add_line(f"{item}", "", indent=4)
            elif isinstance(value, dict):  # Handle nested dictionaries
                add_line(key, "", indent=0)
                for sub_key, sub_value in value.items():
                    add_line(f"{sub_key}", sub_value, indent=2)
            else:  # Handle simple key-value pairs
                add_line(key, value, indent=0)
        
        return "\n".join(formatted)
    return format_system_info(info)

def is_port_in_use(host, port):
    """Check if a port is in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
        except OSError:
            return True
    return False

    



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
    
if __name__ == '__main__':
    print(get_system_info())