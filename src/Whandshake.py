from scapy.all import sniff, wrpcap , EAPOL, Dot11
import os
import sys


class Whandshake:
    def __init__(self):
        self.packets = []

        self.iface = None
        self.channel = None
        self.filename = None

    def handler(self, packet):
        if not packet.haslayer(EAPOL): return
        print(f"Got 1 eapol from {packet[Dot11].addr3}")
        self.packets.append(packet)

    def run_py(self):
        if len(sys.argv) < 4:
            print("Usage : ./handshake_capture.py <ifcae> <channel> <namefile>")

        self.iface = sys.argv[1]
        self.channel = sys.argv[2]
        self.filename = sys.argv[3]

        os.system(f"iwconfig {self.iface} channel {self.channel}")
        sniff (iface = self.iface, prn = self.handler) # ctrl + c
        wrpcap(filename=self.filename,pkt=self.packets)


if __name__ == "__main__":
    Whandshake().run_py()