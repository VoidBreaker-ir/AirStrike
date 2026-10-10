from scapy.all import Dot11 , sniff , Dot11Beacon, Dot11Elt, Dot11ProbeResp, Dot11ProbeReq
from tabulate import tabulate
from threading import Thread
from keyboard import read_key
from os import system
import platform
import sys

class CV:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ITALIC  = "\033[3m"

    # رنگ‌های اصلی VoidBreaker
    VOID    = "\033[38;5;93m"    # بنفش تیره
    PURPLE  = "\033[38;5;135m"   # بنفش
    VIOLET  = "\033[38;5;141m"   # بنفش روشن
    LILAC   = "\033[38;5;183m"   # یاسی
    MAGENTA = "\033[38;5;201m"   # سرخابی
    PINK    = "\033[38;5;213m"   # صورتی
    CYAN    = "\033[38;5;51m"    # فیروزه‌ای
    GREEN   = "\033[38;5;46m"    # سبز نئون
    RED     = "\033[38;5;196m"   # قرمز
    YELLOW  = "\033[38;5;226m"   # زرد
    WHITE   = "\033[38;5;231m"   # سفید
    GRAY    = "\033[38;5;240m"   # خاکستری

    BG_VOID   = "\033[48;5;54m"   # پس‌زمینه بنفش تیره
    BG_PURPLE = "\033[48;5;93m"   # پس‌زمینه بنفش
    BG_LILAC  = "\033[48;5;183m"  # پس‌زمینه یاسی

class Colors:
    """ANSI color codes for terminal output formatting"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def BANNER():
    return f"""
    {CV.PURPLE}██╗   ██╗ ██████╗ ██╗██████╗ ██████╗ ██████╗ ███████╗ █████╗ ██╗  ██╗███████╗██████╗ {CV.VOID}║
    {CV.PURPLE}██║   ██║██╔═══██╗██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██║ ██╔╝██╔════╝██╔══██╗{CV.VOID}║
    {CV.VIOLET}██║   ██║██║   ██║██║██║  ██║██████╔╝██████╔╝█████╗  ███████║█████╔╝ █████╗  ██████╔╝{CV.VOID}║
    {CV.VIOLET}╚██╗ ██╔╝██║   ██║██║██║  ██║██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═██╗ ██╔══╝  ██╔══██╗{CV.VOID}║
    {CV.LILAC} ╚████╔╝ ╚██████╔╝██║██████╔╝██████╔╝██║  ██║███████╗██║  ██║██║  ██╗███████╗██║  ██║{CV.VOID}║
    {CV.LILAC}  ╚═══╝   ╚═════╝ ╚═╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{CV.VOID}║

    """

class WScanner: 
    def __init__(self):
        self.APS = []
        self.STATIONS = []
        self.os_type = platform.system()
        self.channel = 1       

    def _addssidToAP(self, bssid, ssid, channel=None):
        for ap in self.APS:
            if ap["BSSID"] == bssid:
                if channel is not None:
                    ap["CHANNEL"] = channel
                return
        self.APS.append({"SSID": ssid, "BSSID": bssid,
                        "STATIONS": [], "CHANNEL": channel})

    def _addStationToAP(self, bssid, station):
        for ap in self.APS:
            if ap["BSSID"] == bssid:
                if station not in ap['STATIONS']:
                    ap['STATIONS'].append(station)
        for st in self.STATIONS:
            if st["ADDR"] == station:
                st["BSSID"] = bssid
                return 
        self.STATIONS.append({"ADDR" : station, "BSSID" : bssid, "PROBES" : []})        

    def _setUnknowSSID(self, bssid , ssid):
        for ap in self.APS:
            if ap["BSSID"] == bssid:
                ap["SSID"] = ssid
                return

    def _addProbeStation(self,station, ssid):
        if not station:
            return 
        for st in self.STATIONS:
            if st["ADDR"] == station:
                if ssid not in st["PROBES"]: st["PROBES"].append(ssid)
                return 
        self.STATIONS.append({"ADDR" : station, "BSSID" : "not Associaten", "PROBES" : [ssid]})          

    def tabulate_stations(self):
        headers = ["ADDR", "BSSID", "Probes"] ; rows = []
        for st in self.STATIONS:
            rows.append([st["ADDR"], st["BSSID"] , ''.join(st["PROBES"])])
        table = tabulate(rows , headers , tablefmt="rounded_grid")
        return table        

    def tabulate_aps(self): 
        headers = ["SSID" , "BSSID", "STATIONS", "CHANNEL"] ; rows = []
        for ap in self.APS:
            rows.append([ap["SSID"], ap["BSSID"] , ''.join(ap["STATIONS"]), ap["CHANNEL"]])
        table = tabulate(rows , headers , tablefmt="rounded_grid")
        return table
    
    def handler(self, packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode(errors="ignore")
            if packet[Dot11Elt].len == 0 or ssid == "000000000000000000000000000000":
                ssid = "[Unknow]"
            bssid = packet[Dot11].addr2
            channel = None
            elt = packet[Dot11Elt]
            while isinstance(elt, Dot11Elt):
                if elt.ID == 3:
                    channel = elt.info[0]
                    self.channel = channel 
                    break
                elt = elt.payload               
            self._addssidToAP(bssid, ssid, channel)
        elif packet.haslayer(Dot11ProbeResp):
            ssid = packet[Dot11Elt].info.decode(errors="ignore")
            bssid = packet[Dot11].addr2         
            self._setUnknowSSID(bssid, ssid)
        elif packet.haslayer(Dot11ProbeReq):
            ssid = packet[Dot11Elt].info.decode(errors="ignore")
            station = packet[Dot11].addr2
            self._addProbeStation(station, ssid)
        else:
            if packet.haslayer(Dot11):
                to_DS = packet[Dot11].FCfield.to_DS
                from_DS = packet[Dot11].FCfield.from_DS
                if to_DS == 1 and from_DS == 0:
                    self._addStationToAP(packet[Dot11].addr3, packet[Dot11].addr2)
        self.refreshScreen()

    def start(self, add=15, channel=None, count=10, iface="wlan0", **kwargs):
        if channel is not None:
            system(f"iw dev {iface} set channel {channel}")
            sniff(iface=iface, prn=self.handler, **kwargs)
            return
        ch = 1
        while True:
            system(f"iw dev {iface} set channel {ch}")
            sniff(iface=iface, prn=self.handler, count=count, **kwargs)
            ch = 1 if ch == add else ch + 1

    def refreshScreen(self):
        if self.os_type == "Windows":
            system("cls") 
        else:
            system("clear")
        colors = Colors()
        print(BANNER())
        print(colors.HEADER+"Wifi Scanner")
        print(colors.BLUE+"-"*80) 
        print(f"Channel = {self.channel}\n", end='', flush=True)
        print(colors.FAIL+"APS:")
        print("\n", colors.GREEN+self.tabulate_aps())
        print(colors.CYAN+"*"*80)
        print(colors.FAIL+"STATIONS:")
        print("\n", colors.GREEN+self.tabulate_stations())
        print(colors.BLUE+"-"*80)         

    def run_py(self):
        argv = sys.argv
        data = {
            "add" : 15,
            "channel" : None,
            "count" : 10,
            "iface" : None
        }
        data["iface"] = argv[1] if len(argv) >= 2 else "wlan0"
        for i,text in enumerate(argv):
            if text == "-c":
                data["channel"] = argv[i+1]             
            if text == "-add":
                data["add"] = argv[i+1]
            if text == "-count":
                data["count"] = argv[i+1]
            if text == "-o":
                for item in argv[i+1:]:
                    key, value = item.split("=")  
                    data[key] = value

        for key, value in data.items():
            try:
                data[key] = int(value)
            except (ValueError, TypeError):
                continue
        self.start(**data)

    def close(self, key = "Q"):
        while True:
            keyboard = read_key()
            if keyboard.lower() == key.lower():
                return sys.exit()

    def run(self, i = False, **kwargs):
        if self.os_type == "Windows":
            t = Thread(target=self.close)
            t.start()
            self._test()
            return 
        
        t = Thread(target=self.close)
        t.start()
        if i:
            return self.start(**kwargs)
        self.run_py()        

    def _test(self):
        self._addssidToAP("bssid", ssid="ssid", channel=12)
        self._addStationToAP("bssid", station="station")
        self._addStationToAP("bssid2", station="station")   
        self._addProbeStation("station","ssid")     
        self._addProbeStation("station2","ssid") 
        self.refreshScreen()

if __name__ == "__main__":
    ws = WScanner()
    ws.run()

    
 
