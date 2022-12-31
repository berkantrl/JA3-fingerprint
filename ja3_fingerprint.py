#!/usr/bin/python3

"""
By sniffing the packets
takes the ja3 fingerprints of the packets and forwards
the packets to the specified ports according to these fingerprints.
"""

import queue
from scapy.layers.tls.all import TLSClientHello, TLS, TLSSession
import scapy.all as scapy
import hashlib

# Create a queue
q = queue.Queue() 

class Get:
    """Main Get Class"""

    def __init__(self,client_hello) -> None:
        self.client_hello = client_hello
    
    def ciphers(self):
        "Gets Ciphers in Client Hello Packet"
        lst_ciphers = [] 

        for cipher in self.client_hello.ciphers:
            lst_ciphers.append(str(cipher))

        str_ciphers = '-'.join(lst_ciphers)
        return str_ciphers
    
    def version(self):
        """Gets TLSVersion"""
        version = self.client_hello.version
        return version

    def extensions(self):
        """Gets Extension in Client Hello Packet"""
        lst_extensions = []

        for extension in self.client_hello.ext:
            lst_extensions.append(str(extension.type))

        str_extensions = '-'.join(lst_extensions)
        return str_extensions

    def EllipticCurves(self):
        """Gets Elliptic Curves"""
        groups = []

        for extension in self.client_hello.ext:
            try:
                groups = extension.groups
            except:
                continue
        
        groups = list(map(str,groups))
        lst_groups = '-'.join(groups)
        return lst_groups

    def ja3_fingerprint(self):
        """Gets the hash of the ja3 string value"""
        try:
            tlsversion = self.version()
            cipher = self.ciphers()
            extension = self.extensions()
            group = self.EllipticCurves()
            ja3 = f"{tlsversion},{cipher},{extension},{group},0"

            hash = hashlib.md5()
            hash.update(ja3.encode())
            ja3_fingerprint = hash.hexdigest()
            return ja3_fingerprint
        except:
            return "None"


def print_ja3():
    while not q.empty():
        packet = q.get()
        if packet.haslayer(TLS) and packet[TLS].haslayer(TLSClientHello):
            client_hello = packet[TLS][TLSClientHello]
            get = Get(client_hello)
            ja3_fingerprint = get.ja3_fingerprint()
            print(ja3_fingerprint)

def add_packet_to_queue(packet):
    # Add the packet to the queue
    q.put(packet)
    print_ja3()

if __name__ == '__main__':
    # Start sniffing
    scapy.sniff(filter="tcp port 443",prn=add_packet_to_queue,session=TLSSession)