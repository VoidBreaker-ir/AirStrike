"""
WScanner - Wi-Fi Network Scanner with Live Terminal UI
======================================================

Passively scans 802.11 traffic on a monitor-mode wireless interface
and displays discovered access points (APs), stations (clients), and
probe requests in a live terminal table.

Features:
    - Access points: SSID, BSSID, channel, associated stations.
    - Stations: MAC address, associated BSSID, probed SSIDs.
    - Channel hopping across a configurable range.
    - Live refresh of the terminal display.
    - Press 'Q' at any time to quit.

WARNING:
    Requires root and a wireless interface in monitor mode.
    Use only on networks you own or are authorized to audit.

Requirements:
    - Python 3
    - Scapy (pip install scapy)
    - tabulate (pip install tabulate)
    - keyboard (pip install keyboard) — optional, for the 'Q' hotkey

Usage:
    sudo python wscanner.py <iface> [-c CHANNEL] [-add MAX_CH] [-count N] [-o key=value ...]

Arguments:
    iface       : Wireless interface in monitor mode (e.g. wlan0mon).
    -c CHANNEL  : Lock to a single channel instead of hopping.
    -add MAX_CH : Highest channel to hop to (default: 15).
    -count N    : Packets to capture per channel before hopping (default: 10).
    -o key=value: Extra keyword arguments forwarded to scapy.sniff().

Example:
    sudo python wscanner.py wlan0mon -c 6
    sudo python wscanner.py wlan0mon -add 11 -count 20
"""

from scapy.all import (
    Dot11, sniff, Dot11Beacon, Dot11Elt, Dot11ProbeResp, Dot11ProbeReq,
)
from tabulate import tabulate
from threading import Thread
from os import system, _exit
import platform
import sys

try:
    from keyboard import read_key
    HAS_KEYBOARD = True
except ImportError:
    HAS_KEYBOARD = False


class CV:
    """ANSI color codes (VoidBreaker theme)."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ITALIC  = "\033[3m"

    VOID    = "\033[38;5;93m"
    PURPLE  = "\033[38;5;135m"
    VIOLET  = "\033[38;5;141m"
    LILAC   = "\033[38;5;183m"
    MAGENTA = "\033[38;5;201m"
    PINK    = "\033[38;5;213m"
    CYAN    = "\033[38;5;51m"
    GREEN   = "\033[38;5;46m"
    RED     = "\033[38;5;196m"
    YELLOW  = "\033[38;5;226m"
    WHITE   = "\033[38;5;231m"
    GRAY    = "\033[38;5;240m"

    BG_VOID   = "\033[48;5;54m"
    BG_PURPLE = "\033[48;5;93m"
    BG_LILAC  = "\033[48;5;183m"


BANNER_TEXT = f"""
    {CV.PURPLE}██╗   ██╗ ██████╗ ██╗██████╗ ██████╗ ██████╗ ███████╗ █████╗ ██╗  ██╗███████╗██████╗ {CV.VOID}║
    {CV.PURPLE}██║   ██║██╔═══██╗██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██║ ██╔╝██╔════╝██╔══██╗{CV.VOID}║
    {CV.VIOLET}██║   ██║██║   ██║██║██║  ██║██████╔╝██████╔╝█████╗  ███████║█████╔╝ █████╗  ██████╔╝{CV.VOID}║
    {CV.VIOLET}╚██╗ ██╔╝██║   ██║██║██║  ██║██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═██╗ ██╔══╝  ██╔══██╗{CV.VOID}║
    {CV.LILAC} ╚████╔╝ ╚██████╔╝██║██████╔╝██████╔╝██║  ██║███████╗██║  ██║██║  ██╗███████╗██║  ██║{CV.VOID}║
    {CV.LILAC}  ╚═══╝   ╚═════╝ ╚═╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{CV.VOID}║
"""


def BANNER():
    """Return the ASCII banner with ANSI colors applied."""
    return BANNER_TEXT


class WScanner:
    """
    Live Wi-Fi scanner with terminal UI.

    Attributes:
        APS (list[dict]): Discovered access points. Each entry has keys
            "SSID", "BSSID", "STATIONS" (list), "CHANNEL" (int | None).
        STATIONS (list[dict]): Discovered stations. Each entry has keys
            "ADDR", "BSSID", "PROBES" (list).
        os_type (str): platform.system() result.
        current_scan_channel (int): Channel currently locked on iface.
        stop (bool): Set to True to stop the sniff loop cleanly.
    """

    def __init__(self):
        """Initialize empty scanner state."""
        self.APS = []
        self.STATIONS = []
        self.os_type = platform.system()
        self.current_scan_channel = 1
        self.stop = False

    # ------------------------------------------------------------------
    # Internal data-structure helpers
    # ------------------------------------------------------------------

    def _addssidToAP(self, bssid, ssid, channel=None):
        """
        Add or update an access point entry.

        Args:
            bssid (str): AP MAC address.
            ssid (str): Network name.
            channel (int | None): Optional channel number.
        """
        for ap in self.APS:
            if ap["BSSID"] == bssid:
                if channel is not None:
                    ap["CHANNEL"] = channel
                # Only replace [Unknow] with a real SSID.
                if ap["SSID"] == "[Unknow]" and ssid != "[Unknow]":
                    ap["SSID"] = ssid
                return
        self.APS.append({"SSID": ssid, "BSSID": bssid,
                         "STATIONS": [], "CHANNEL": channel})

    def _addStationToAP(self, bssid, station):
        """
        Associate a station MAC with an AP.

        Args:
            bssid (str): AP MAC address.
            station (str): Station MAC address.
        """
        for ap in self.APS:
            if ap["BSSID"] == bssid:
                if station not in ap["STATIONS"]:
                    ap["STATIONS"].append(station)

        for st in self.STATIONS:
            if st["ADDR"] == station:
                st["BSSID"] = bssid
                return
        self.STATIONS.append({"ADDR": station, "BSSID": bssid, "PROBES": []})

    def _setUnknowSSID(self, bssid, ssid):
        """
        Replace a placeholder SSID once a probe response reveals it.

        Args:
            bssid (str): AP MAC address.
            ssid (str): Revealed SSID.
        """
        for ap in self.APS:
            if ap["BSSID"] == bssid and ap["SSID"] == "[Unknow]":
                ap["SSID"] = ssid
                return

    def _addProbeStation(self, station, ssid):
        """
        Record a probe request from a station.

        Args:
            station (str): Station MAC address (may be empty for random MACs).
            ssid (str): Probed SSID.
        """
        if not station:
            return
        for st in self.STATIONS:
            if st["ADDR"] == station:
                if ssid not in st["PROBES"]:
                    st["PROBES"].append(ssid)
                return
        self.STATIONS.append({"ADDR": station,
                              "BSSID": "not Associated",
                              "PROBES": [ssid]})

    # ------------------------------------------------------------------
    # Table rendering
    # ------------------------------------------------------------------

    def tabulate_stations(self):
        """Return a formatted table of discovered stations."""
        headers = ["ADDR", "BSSID", "Probes"]
        rows = [[st["ADDR"], st["BSSID"], ", ".join(st["PROBES"])]
                for st in self.STATIONS]
        return tabulate(rows, headers, tablefmt="rounded_grid")

    def tabulate_aps(self):
        """Return a formatted table of discovered access points."""
        headers = ["SSID", "BSSID", "STATIONS", "CHANNEL"]
        rows = [[ap["SSID"], ap["BSSID"],
                 ", ".join(ap["STATIONS"]), ap["CHANNEL"]]
                for ap in self.APS]
        return tabulate(rows, headers, tablefmt="rounded_grid")

    # ------------------------------------------------------------------
    # Packet handler
    # ------------------------------------------------------------------

    def _extract_ssid(self, packet):
        """
        Safely extract the SSID from a management frame.

        Returns "[Unknow]" for hidden networks or frames without an
        SSID element.
        """
        elt = packet.getlayer(Dot11Elt)
        while elt is not None and elt.ID != 0:
            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
        if elt is None or elt.len == 0:
            return "[Unknow]"
        try:
            return elt.info.decode("utf-8", errors="ignore") or "[Unknow]"
        except Exception:
            return "[Unknow]"

    def _extract_channel(self, packet):
        """Extract the channel from the DS Parameter Set (ID 3), or None."""
        elt = packet.getlayer(Dot11Elt)
        while elt is not None:
            if elt.ID == 3:
                return elt.info[0]
            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
        return None

    def handler(self, packet):
        """
        Scapy callback: parse each captured frame.

        Handles:
            - Beacons      -> AP discovery (SSID, BSSID, channel).
            - ProbeResp    -> SSID revelation for hidden networks.
            - ProbeReq     -> Station probe tracking.
            - Data frames  -> Station-to-AP association via DS bits.

        Args:
            packet: A Scapy packet.
        """
        if not packet.haslayer(Dot11):
            return

        if packet.haslayer(Dot11Beacon):
            ssid = self._extract_ssid(packet)
            bssid = packet[Dot11].addr2
            channel = self._extract_channel(packet)
            self._addssidToAP(bssid, ssid, channel)

        elif packet.haslayer(Dot11ProbeResp):
            ssid = self._extract_ssid(packet)
            bssid = packet[Dot11].addr2
            self._setUnknowSSID(bssid, ssid)

        elif packet.haslayer(Dot11ProbeReq):
            ssid = self._extract_ssid(packet)
            station = packet[Dot11].addr2
            self._addProbeStation(station, ssid)

        else:
            fc = packet[Dot11].FCfield
            to_ds = fc & 0x1
            from_ds = fc & 0x2
            if to_ds and not from_ds:
                self._addStationToAP(packet[Dot11].addr3,
                                     packet[Dot11].addr2)

        self.refreshScreen()

    # ------------------------------------------------------------------
    # Scanning loop
    # ------------------------------------------------------------------

    def start(self, add=15, channel=None, count=10, iface="wlan0", **kwargs):
        """
        Start scanning. If `channel` is set, lock to it; otherwise hop
        channels 1..add.

        Args:
            add (int): Highest channel to hop to. Default 15.
            channel (int | None): If set, lock to this channel.
            count (int): Packets per channel before hopping. Default 10.
            iface (str): Wireless interface in monitor mode.
            **kwargs: Extra args forwarded to scapy.sniff().
        """
        if channel is not None:
            self.current_scan_channel = channel
            system(f"iw dev {iface} set channel {channel}")
            try:
                sniff(iface=iface, prn=self.handler, **kwargs)
            except KeyboardInterrupt:
                pass
            return

        ch = 1
        try:
            while not self.stop:
                self.current_scan_channel = ch
                system(f"iw dev {iface} set channel {ch}")
                sniff(iface=iface, prn=self.handler, count=count, **kwargs)
                ch = 1 if ch >= add else ch + 1
        except KeyboardInterrupt:
            pass

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def refreshScreen(self):
        """Clear the terminal and redraw the current state."""
        # Fast, flicker-free clear.
        print("\033[H\033[J", end="")

        print(BANNER())
        print(CV.HEADER if hasattr(CV, "HEADER") else CV.CYAN, "Wifi Scanner")
        print(CV.BLUE if hasattr(CV, "BLUE") else CV.CYAN, "-" * 80)
        print(f"Channel = {self.current_scan_channel}\n", end="", flush=True)
        print(CV.RED, "APS:")
        print("\n", CV.GREEN + self.tabulate_aps())
        print(CV.CYAN + "*" * 80)
        print(CV.RED, "STATIONS:")
        print("\n", CV.GREEN + self.tabulate_stations())
        print(CV.CYAN + "-" * 80)

    # ------------------------------------------------------------------
    # CLI + lifecycle
    # ------------------------------------------------------------------

    def run_py(self):
        """
        Parse CLI arguments and start scanning.

        Supported flags:
            iface       : first positional argument (default: wlan0)
            -c CHANNEL  : lock to a channel
            -add N      : highest channel to hop to
            -count N    : packets per channel
            -o k=v ...  : extra sniff() kwargs
        """
        argv = sys.argv
        data = {"add": 15, "channel": None, "count": 10, "iface": "wlan0"}

        # First positional argument = interface (only if it isn't a flag).
        if len(argv) >= 2 and not argv[1].startswith("-"):
            data["iface"] = argv[1]

        i = 1
        while i < len(argv):
            text = argv[i]
            if text == "-c" and i + 1 < len(argv):
                data["channel"] = argv[i + 1]
                i += 2
                continue
            if text == "-add" and i + 1 < len(argv):
                data["add"] = argv[i + 1]
                i += 2
                continue
            if text == "-count" and i + 1 < len(argv):
                data["count"] = argv[i + 1]
                i += 2
                continue
            if text == "-o":
                for item in argv[i + 1:]:
                    if "=" in item:
                        key, value = item.split("=", 1)
                        data[key] = value
                break
            i += 1

        # Coerce ints where possible.
        for key in ("add", "count", "channel"):
            if data.get(key) is not None:
                try:
                    data[key] = int(data[key])
                except (ValueError, TypeError):
                    pass

        self.start(**data)

    def close(self, key="Q"):
        """
        Listen for a quit key on a background thread and terminate
        the process when pressed.

        Args:
            key (str): Hotkey that quits the scanner. Default "Q".
        """
        if not HAS_KEYBOARD:
            return
        while not self.stop:
            try:
                k = read_key()
            except Exception:
                return
            if k.lower() == key.lower():
                self.stop = True
                _exit(0)  # hard-exit from any thread

    def run(self, i=False, **kwargs):
        """
        Entry point. Starts the quit-hotkey thread and the scanner.

        Args:
            i (bool): If True, call start(**kwargs) directly (used for
                programmatic use); otherwise parse CLI args.
            **kwargs: Forwarded to start() when i=True.
        """
        if HAS_KEYBOARD:
            t = Thread(target=self.close, daemon=True)
            t.start()

        if i:
            return self.start(**kwargs)
        self.run_py()

    # ------------------------------------------------------------------
    # Self-test
    # ------------------------------------------------------------------

    def _test(self):
        """Inject sample data and render the UI (development only)."""
        self._addssidToAP("bssid", "ssid", channel=12)
        self._addStationToAP("bssid", "station")
        self._addStationToAP("bssid2", "station")
        self._addProbeStation("station", "ssid")
        self._addProbeStation("station2", "ssid")
        self.refreshScreen()


if __name__ == "__main__":
    WScanner().run()