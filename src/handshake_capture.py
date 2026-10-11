"""
Handshake Capture Tool
======================

Capture EAPOL (802.1X) frames from a wireless interface and save them
to a pcap file. EAPOL frames carry the WPA/WPA2 4-way handshake, which
can later be used with tools such as `aircrack-ng` or `hashcat` for
offline password auditing (only on networks you are authorized to test).

Requirements:
    - Python 3
    - Scapy (pip install scapy)
    - Root privileges
    - A wireless adapter in MONITOR MODE
    - `iw` (from the `iw` package) or `iwconfig` (wireless-tools)

Usage:
    sudo python ./handshake_capture.py <iface> <channel> <namefile>

Arguments:
    iface    : Wireless interface in monitor mode (e.g., wlan0mon).
    channel  : Wi-Fi channel to lock the interface to (1-14 or 36-165).
    namefile : Output pcap file path (e.g., handshake.pcap).

Example:
    sudo python ./handshake_capture.py wlan0mon 6 handshake.pcap

Notes:
    Press Ctrl+C to stop the capture. Any EAPOL frames collected up to
    that point will be written to the output file.
"""

from scapy.all import sniff, wrpcap, EAPOL, Dot11
import os
import sys
import subprocess


class Handshake:
    """
    Capture EAPOL handshake frames from a wireless interface.

    Attributes:
        packets (list): Collected EAPOL packets (Scapy objects).
        iface (str | None): Wireless interface name.
        channel (str | None): Wi-Fi channel to lock the interface to.
        filename (str | None): Output pcap file path.
    """

    def __init__(self):
        """Initialize an empty packet buffer and unset parameters."""
        self.packets = []
        self.iface = None
        self.channel = None
        self.filename = None

    def handler(self, packet):
        """
        Scapy sniff callback. Append EAPOL packets to the buffer.

        Args:
            packet: A Scapy packet received by `sniff`.
        """
        if not packet.haslayer(EAPOL):
            return
        print(f"[+] Got 1 EAPOL from {packet[Dot11].addr3}")
        self.packets.append(packet)

    def _set_channel(self):
        """
        Lock the wireless interface to the requested channel.

        Uses `iw` (preferred, modern) and falls back to `iwconfig`
        (deprecated) if `iw` is not available.

        Raises:
            subprocess.CalledProcessError: If neither tool succeeds.
        """
        try:
            subprocess.run(
                ["iw", "dev", self.iface, "set", "channel", self.channel],
                check=True,
                capture_output=True,
                text=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError):
            # Fallback to iwconfig (older systems).
            subprocess.run(
                ["iwconfig", self.iface, "channel", self.channel],
                check=True,
                capture_output=True,
                text=True,
            )

    def run_py(self):
        """
        Parse CLI arguments, set the channel, sniff EAPOL frames, and
        save them to a pcap file when interrupted by Ctrl+C.

        Behavior:
            - Validates argc; exits with code 1 on usage error.
            - Sets the interface channel using `iw` or `iwconfig`.
            - Runs `sniff()` with `store=0` to avoid buffering every
              packet in memory, and with an EAPOL-only BPF filter to
              reduce CPU load.
            - Catches KeyboardInterrupt so the pcap is still written.
        """
        if len(sys.argv) < 4:
            print("Usage: sudo python ./handshake_capture.py <iface> <channel> <namefile>")
            sys.exit(1)

        self.iface = sys.argv[1]
        self.channel = sys.argv[2]
        self.filename = sys.argv[3]

        try:
            self._set_channel()
        except Exception as e:
            print(f"[!] Failed to set channel: {e}")
            sys.exit(1)

        print(f"[*] Sniffing on {self.iface} (channel {self.channel}). "
              f"Press Ctrl+C to stop.")

        try:
            # store=0: do not keep every packet in memory.
            # filter: only deliver EAPOL frames (EtherType 0x888e).
            sniff(
                iface=self.iface,
                prn=self.handler,
                store=0,
                filter="ether proto 0x888e",
            )
        except KeyboardInterrupt:
            pass
        finally:
            if self.packets:
                wrpcap(self.filename, self.packets)
                print(f"[+] Saved {len(self.packets)} EAPOL frame(s) "
                      f"to {self.filename}")
            else:
                print("[!] No EAPOL frames captured. Nothing to save.")


if __name__ == "__main__":
    Handshake().run_py()